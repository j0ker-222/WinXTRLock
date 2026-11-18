//go:build windows

// winxtrlock - минимальный блокировщик ввода для Windows 10/11,
// аналог jarun/xtrlock под X11.
//
// Поведение как у оригинала:
//   - рабочий стол остаётся виден, никаких перекрывающих окон
//   - клавиатура и мышь перехватываются (курсор замирает - это и есть
//     визуальный признак блокировки, как замок-курсор в xtrlock)
//   - разблокировка: набрать пароль от своей учётной записи и нажать Enter
//
// Пароль нигде не хранится: при Enter введённое проверяется через
// LogonUser против текущей учётной записи (локальной или доменной),
// ровно как xtrlock сверяет с паролем сессии.
//
// Это ЛИЧНЫЙ блокировщик, а не граница безопасности. Ctrl+Alt+Del
// (Secure Attention Sequence) перехватить из пользовательского режима
// нельзя - это штатный аварийный выход, и именно поэтому инструмент
// не ведёт себя как вымогатель: владелец машины всегда может выйти.
//
// Зависимостей нет - только стандартная библиотека.
package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	whKeyboardLL = 13
	whMouseLL    = 14
	hcAction     = 0

	wmKeydown    = 0x0100
	wmSyskeydown = 0x0104
	wmApp        = 0x8000 // наш сигнал "пароль верный, выходим"

	vkReturn = 0x0D
	vkBack   = 0x08
	vkEscape = 0x1B

	logon32LogonNetwork    = 3 // быстрая проверка учётных данных
	logon32ProviderDefault = 0
)

// KBDLLHOOKSTRUCT из WinAPI
type kbdllhookstruct struct {
	vkCode      uint32
	scanCode    uint32
	flags       uint32
	time        uint32
	dwExtraInfo uintptr
}

type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	ptX     int32
	ptY     int32
}

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procSetWindowsHookEx    = user32.NewProc("SetWindowsHookExW")
	procCallNextHookEx      = user32.NewProc("CallNextHookEx")
	procUnhookWindowsHookEx = user32.NewProc("UnhookWindowsHookEx")
	procGetMessage          = user32.NewProc("GetMessageW")
	procToUnicode           = user32.NewProc("ToUnicode")
	procGetKeyboardState    = user32.NewProc("GetKeyboardState")
	procPostThreadMessage   = user32.NewProc("PostThreadMessageW")

	procGetModuleHandle    = kernel32.NewProc("GetModuleHandleW")
	procGetCurrentThreadId = kernel32.NewProc("GetCurrentThreadId")
	procCloseHandle        = kernel32.NewProc("CloseHandle")

	procLogonUser = advapi32.NewProc("LogonUserW")

	kbHook       uintptr
	mouseHook    uintptr
	passBuf      []rune
	checkCh      chan string
	hookThreadID uintptr
)

func keyboardState() [256]byte {
	var s [256]byte
	procGetKeyboardState.Call(uintptr(unsafe.Pointer(&s[0])))
	return s
}

// vkToRune переводит код клавиши в символ с учётом раскладки, Shift и Caps.
func vkToRune(vk, scan uint32) rune {
	s := keyboardState()
	var buf [8]uint16
	r, _, _ := procToUnicode.Call(
		uintptr(vk),
		uintptr(scan),
		uintptr(unsafe.Pointer(&s[0])),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
	)
	if int32(r) == 1 {
		return rune(buf[0])
	}
	return 0
}

// validPassword проверяет пароль против текущей учётной записи.
// Ничего не хранит: удачный LogonUser = пароль верный.
func validPassword(pw string) bool {
	user, _ := syscall.UTF16PtrFromString(os.Getenv("USERNAME"))
	dom := os.Getenv("USERDOMAIN")
	if dom == "" {
		dom = "."
	}
	domP, _ := syscall.UTF16PtrFromString(dom)
	passP, _ := syscall.UTF16PtrFromString(pw)

	var token syscall.Handle
	r, _, _ := procLogonUser.Call(
		uintptr(unsafe.Pointer(user)),
		uintptr(unsafe.Pointer(domP)),
		uintptr(unsafe.Pointer(passP)),
		logon32LogonNetwork,
		logon32ProviderDefault,
		uintptr(unsafe.Pointer(&token)),
	)
	if r != 0 {
		if token != 0 {
			procCloseHandle.Call(uintptr(token))
		}
		return true
	}
	return false
}

// validator крутится в отдельной горутине, чтобы LogonUser не выполнялся
// внутри колбэка хука (у LL-хуков есть таймаут обработки ~300 мс).
func validator() {
	for pw := range checkCh {
		if validPassword(pw) {
			procPostThreadMessage.Call(hookThreadID, wmApp, 0, 0)
			return
		}
	}
}

func keyboardProc(nCode, wParam, lParam uintptr) uintptr {
	if int32(nCode) == hcAction {
		kb := (*kbdllhookstruct)(unsafe.Pointer(lParam))
		if wParam == wmKeydown || wParam == wmSyskeydown {
			switch kb.vkCode {
			case vkReturn:
				// отдаём пароль валидатору не блокируя хук
				select {
				case checkCh <- string(passBuf):
				default:
				}
				for i := range passBuf {
					passBuf[i] = 0
				}
				passBuf = passBuf[:0]
			case vkBack:
				if len(passBuf) > 0 {
					passBuf = passBuf[:len(passBuf)-1]
				}
			case vkEscape:
				passBuf = passBuf[:0]
			default:
				if r := vkToRune(kb.vkCode, kb.scanCode); r != 0 {
					passBuf = append(passBuf, r)
				}
			}
		}
		// глотаем весь клавиатурный ввод, чтобы он не доходил до приложений
		return 1
	}
	ret, _, _ := procCallNextHookEx.Call(0, nCode, wParam, lParam)
	return ret
}

func mouseProc(nCode, wParam, lParam uintptr) uintptr {
	if int32(nCode) == hcAction {
		// глотаем все события мыши: курсор замирает - признак блокировки
		return 1
	}
	ret, _, _ := procCallNextHookEx.Call(0, nCode, wParam, lParam)
	return ret
}

func lock() error {
	// LL-хуки и их цикл сообщений должны жить на одном потоке ОС
	runtime.LockOSThread()

	hookThreadID, _, _ = procGetCurrentThreadId.Call()
	checkCh = make(chan string, 4)
	go validator()

	mod, _, _ := procGetModuleHandle.Call(0)
	kbCb := syscall.NewCallback(keyboardProc)
	msCb := syscall.NewCallback(mouseProc)

	kbHook, _, _ = procSetWindowsHookEx.Call(whKeyboardLL, kbCb, mod, 0)
	if kbHook == 0 {
		return fmt.Errorf("не удалось установить клавиатурный хук")
	}
	mouseHook, _, _ = procSetWindowsHookEx.Call(whMouseLL, msCb, mod, 0)
	if mouseHook == 0 {
		procUnhookWindowsHookEx.Call(kbHook)
		kbHook = 0
		return fmt.Errorf("не удалось установить мышиный хук")
	}

	// цикл сообщений: LL-хуки без него не сработают.
	// выход либо по WM_QUIT, либо по нашему wmApp (пароль верный).
	var m msg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 { // 0 = WM_QUIT, -1 = ошибка
			break
		}
		if m.message == wmApp {
			break
		}
	}

	if kbHook != 0 {
		procUnhookWindowsHookEx.Call(kbHook)
		kbHook = 0
	}
	if mouseHook != 0 {
		procUnhookWindowsHookEx.Call(mouseHook)
		mouseHook = 0
	}
	return nil
}

func usage() {
	fmt.Println(`winxtrlock - блокировщик ввода (аналог xtrlock) для Windows

Использование:
  winxtrlock          заблокировать ввод (рабочий стол остаётся виден)
  winxtrlock -h       справка

Разблокировка: набрать пароль от своей учётной записи Windows и нажать Enter.
Аварийный выход всегда доступен через Ctrl+Alt+Del.`)
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-h", "--help", "/?":
			usage()
			return
		}
	}

	if err := lock(); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}
