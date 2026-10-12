/*
    Generic defensive static indicator:
    PE imports the classic process-injection API combination
    (allocate in remote process + write + start remote thread).

    Many legitimate tools (debuggers, AV/EDR products, game overlays) also
    import these APIs, so treat a match as a prompt for review, not a verdict.
*/

import "pe"

rule Process_Injection_API_Combination
{
    meta:
        description = "PE imports a combination of APIs commonly used for process injection (VirtualAllocEx + WriteProcessMemory + remote thread creation)"
        author = "malware-triage-toolkit"
        category = "static-indicator"
        behaviour = "process-injection"

    condition:
        pe.is_pe
        and pe.imports("kernel32.dll", "VirtualAllocEx")
        and pe.imports("kernel32.dll", "WriteProcessMemory")
        and (
            pe.imports("kernel32.dll", "CreateRemoteThread")
            or pe.imports("kernel32.dll", "CreateRemoteThreadEx")
            or pe.imports("ntdll.dll", "NtCreateThreadEx")
            or pe.imports("ntdll.dll", "RtlCreateUserThread")
        )
}
