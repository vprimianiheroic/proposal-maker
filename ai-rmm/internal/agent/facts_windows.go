//go:build windows

package agent

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/airmm/airmm/internal/protocol"
)

var procGetTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

func platformFacts(f *protocol.Facts) {
	// 64-bit registry view even from the 32-bit agent build.
	const view = registry.WOW64_64KEY
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|view); err == nil {
		f.OSName, _, _ = k.GetStringValue("ProductName")
		build, _, _ := k.GetStringValue("CurrentBuildNumber")
		ubr, _, _ := k.GetIntegerValue("UBR")
		major, _, errMaj := k.GetIntegerValue("CurrentMajorVersionNumber")
		minor, _, _ := k.GetIntegerValue("CurrentMinorVersionNumber")
		if errMaj == nil {
			f.OSVersion = fmt.Sprintf("%d.%d.%s", major, minor, build)
		} else {
			cv, _, _ := k.GetStringValue("CurrentVersion") // 6.1 = Win7/2008R2, 6.3 = 8.1/2012R2
			f.OSVersion = cv + "." + build
		}
		f.OSBuild = build
		if ubr > 0 {
			f.OSBuild = fmt.Sprintf("%s.%d", build, ubr)
		}
		if dv, _, err := k.GetStringValue("DisplayVersion"); err == nil && dv != "" {
			f.OSName += " " + dv
		}
		// Windows 11 still reports "Windows 10" in ProductName.
		if n, _ := strconv.Atoi(build); n >= 22000 && strings.Contains(f.OSName, "Windows 10") {
			f.OSName = strings.Replace(f.OSName, "Windows 10", "Windows 11", 1)
		}
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\ProductOptions`, registry.QUERY_VALUE|view); err == nil {
		pt, _, _ := k.GetStringValue("ProductType")
		switch pt {
		case "WinNT":
			f.ProductType = "workstation"
		case "LanmanNT":
			f.ProductType = "domain_controller"
		case "ServerNT":
			f.ProductType = "server"
		}
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine`, registry.QUERY_VALUE|view); err == nil {
		f.PSVersion, _, _ = k.GetStringValue("PowerShellVersion")
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, registry.QUERY_VALUE|view); err == nil {
		if a, _, err := k.GetStringValue("PROCESSOR_ARCHITECTURE"); err == nil {
			switch strings.ToUpper(a) {
			case "AMD64":
				f.OSArch = "amd64"
			case "X86":
				f.OSArch = "386"
			case "ARM64":
				f.OSArch = "arm64"
			}
		}
		k.Close()
	}

	var name *uint16
	var status uint32
	if err := windows.NetGetJoinInformation(nil, &name, &status); err == nil {
		if status == windows.NetSetupDomainName {
			f.DomainJoined = true
		}
		windows.NetApiBufferFree((*byte)(unsafe.Pointer(name)))
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE); err == nil {
		f.Domain, _, _ = k.GetStringValue("Domain")
		if f.Domain == "" {
			f.Domain, _, _ = k.GetStringValue("NV Domain")
		}
		k.Close()
	}
	if r, _, _ := syscall.SyscallN(procGetTickCount64.Addr()); r != 0 {
		f.BootTime = time.Now().Add(-time.Duration(r) * time.Millisecond).Unix()
	}
}
