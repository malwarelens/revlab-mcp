/*
    Generic defensive static indicator:
    Strings referencing the Windows registry Run / RunOnce keys, a very
    common autostart (persistence) location.

    Countless legitimate applications register autostart entries here too,
    so a match means "check what is being launched", not "malicious".
*/

rule Persistence_Run_Key_Strings
{
    meta:
        description = "Contains strings referencing the registry Run/RunOnce autostart keys, a common persistence location"
        author = "malware-triage-toolkit"
        category = "static-indicator"
        behaviour = "persistence"

    strings:
        $run_soft = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $runonce_soft = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $run_cv = "\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $runonce_cv = "\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase

    condition:
        any of them
}
