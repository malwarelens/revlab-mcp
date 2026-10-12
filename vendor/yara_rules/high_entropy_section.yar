/*
    Generic defensive static indicator:
    A PE section whose raw data has very high entropy (> 7.2), which often
    indicates packed, compressed, or encrypted content.

    Installers, self-extracting archives, and legitimately protected
    commercial binaries also match -- review, don't conclude.
*/

import "pe"
import "math"

rule High_Entropy_PE_Section
{
    meta:
        description = "PE contains a section with high entropy (> 7.2), suggesting packed or encrypted content"
        author = "malware-triage-toolkit"
        category = "static-indicator"
        behaviour = "packing"

    condition:
        pe.is_pe
        and for any section in pe.sections : (
            section.raw_data_size > 0
            and math.entropy(section.raw_data_offset, section.raw_data_size) > 7.2
        )
}
