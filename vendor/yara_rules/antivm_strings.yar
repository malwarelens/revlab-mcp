/*
    Generic defensive static indicator:
    Multiple strings associated with virtual-machine / sandbox environment
    checks. Malware often probes for these artifacts to decide whether it
    is being analysed; hypervisor tools and inventory software may also
    contain some of them, which is why at least two distinct strings are
    required for a match.
*/

rule AntiVM_Environment_Strings
{
    meta:
        description = "Contains multiple strings associated with virtual machine / analysis environment detection"
        author = "malware-triage-toolkit"
        category = "static-indicator"
        behaviour = "anti-analysis"

    strings:
        $vmware1 = "VMware" ascii wide nocase
        $vmware2 = "vmtoolsd" ascii wide nocase
        $vmware3 = "vmmouse" ascii wide nocase
        $vbox1 = "VirtualBox" ascii wide nocase
        $vbox2 = "VBoxService" ascii wide nocase
        $vbox3 = "VBoxTray" ascii wide nocase
        $qemu = "QEMU" ascii wide nocase
        $sbie = "SbieDll" ascii wide nocase
        $wine = "wine_get_unix_file_name" ascii wide nocase
        $hyperv = "Hyper-V" ascii wide nocase

    condition:
        2 of them
}
