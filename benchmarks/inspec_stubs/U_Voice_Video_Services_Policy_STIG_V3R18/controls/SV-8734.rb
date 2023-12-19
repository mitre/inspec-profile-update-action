control 'SV-8734' do
  title 'All applicable STIGs have NOT been applied to the VVoIP / unified communications core infrastructure assets.'
  desc "For the purpose of this requirement a VVoIP server is any server directly supporting the communications service.  Unlike a regular PC or print server on the network VVoIP servers are “mission critical” to the operation of the VoIP system. Some vendors provide IP Telephony services on their own proprietary systems while others provided these services on standard UNIX, Linux, and Microsoft Windows based systems. They may also use general-purpose applications such as databases like MS-SQL or Oracle and/or employ web server technology like IIS or similar as well as open source software. Additionally, application security guidance may be applicable for the vendor's application that makes the server or device perform the functions, or the management, of the system. 
Hardening these general purpose applications and operating systems against the much inherent vulnerabilities found in them is critical to  securing the VVoIP core infrastructure, to include their installed applications. Doing so is vital to protecting the VoIP environment from malicious attack. The specific VVoIP system server or device determines the applicability of any given STIG.
UNIX and Microsoft Windows based systems.  Most known vulnerabilities exist on UNIX and Windows based operating systems.  They may also use general-purpose applications such as databases like MS-SQL or Oracle and/or employ web server technology like IIS or similar. Additionally, application security guidance  may be applicable for the vendor's application that makes the server or device perform the functions, or the management, of the system. Therefore, the securing of these voice processing and signaling platforms, to include their installed applications, is vital in protecting the VoIP environment from malicious attack. The specific VoIP system server or device determines the applicability of any given STIG."
  desc 'check', 'Interview the IAO and review site documentation to confirm compliance with the following requirement:
Ensure that the VVoIP core infrastructure servers/devices have been secured and hardened in compliance with all applicable STIGs (i.e., UNIX, Microsoft Windows, database, web, etc.). 

Determine if the asset is based upon any of the general purpose technology (OS or application) for which there is a STIG or checklist. 

Obtain a copy of the applicable SRR or Self Assessment results and review for compliance.  If SRR results are not available, then SRR a representative number of devices. 

This is a finding in the event it is evident that the appropriate STIGs have not been applied. This check is not intended to determine if the asset is in full compliance.

NOTE: If the server/device is purpose built to its function (potentially considered an appliance) using an embedded or stripped down version of a general purpose OS and/or if the device has limited I/O capabilities, it may be difficult to impossible to perform a normal review that would be done on a general purpose platform. In this case the best way to determines if the device is vulnerable is to perform a network scan on it.

NOTE: VVoIP core infrastructure servers/devices include but may not be limited to the TDM telephone switches, local session controller (LSC), voicemail / unified mail system, interactive voice response system, media gateway, signaling gateway, management servers and workstations, conference bridges, IM/presence servers, etc.'
  desc 'fix', 'Secure critical servers supporting the telephony environment. Apply all applicable STIGs (i.e., UNIX, Microsoft Windows, database, web, etc. UNIX, Win2k/NT, DSN, etc.) and ensure compliance with applicable STIG guidelines.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23615r1_chk'
  tag severity: 'low'
  tag gid: 'V-8248'
  tag rid: 'SV-8734r1_rule'
  tag stig_id: 'VVoIP 1030 (GENERAL)'
  tag gtitle: 'Deficient hardening: STIG appl’n to VVOIP assets'
  tag fix_id: 'F-7731r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag potential_impacts: 'Denial of Service and/or unauthorized access to network or voice system resources or services and the information they contain. The DOD voice system may not be protected as required and may be vulnerable to attack or loss of availability due to a multitude of OS and application vulnerabilities.'
  tag responsibility: 'Information Assurance Officer'
end
