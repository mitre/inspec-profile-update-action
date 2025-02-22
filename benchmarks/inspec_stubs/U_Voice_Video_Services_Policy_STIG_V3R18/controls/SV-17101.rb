control 'SV-17101' do
  title 'A PC communications application is not maintained at the current/latest approved patch or version/upgrade level.'
  desc 'Managing, mitigating, or eliminating a newly discovered vulnerably in a communications application is just as important as managing and mitigating the vulnerabilities of the platform supporting the application.  PC communications applications must be patched or upgraded when a security related patch or upgrade is released by the vendor. While many vendors will release a patch to mitigate a vulnerability in an operating system or major application, other vendors will include the fix in a new version of the application. Multiple patches can also be rolled up into an upgrade. It is important to maintain the current patch and upgrade level of any communications applications installed on a PC. The purpose of this is to maintain the highest possible level of security for the application and the communications service(s) it provides.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure PC voice, video, UC, and/or collaboration communications applications are maintained at the current/latest approved patch or version/upgrade level.

Determine if PC voice, video, UC, and/or collaboration communications applications are maintained at the current/latest approved patch or version/upgrade level. Consult with the vendor or their web site to determine if the version that is in use is the latest version that contains the latest IA mitigations. Determine if this version is the latest approved version.'
  desc 'fix', 'Ensure PC voice, video, UC, and/or collaboration communications applications are maintained at the current/latest approved patch or version/upgrade level.

Implement the current/latest approved patch or version/upgrade level to utilize the latest IA mitigations. If an outdated application version is no longer in use, un-install it. If the latest version is not approved, submit it for testing and approval to ensure the latest IA mitigations are available and used.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17157r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16113'
  tag rid: 'SV-17101r1_rule'
  tag stig_id: 'VVoIP 1700 (GENERAL)'
  tag gtitle: 'Deficient Imp’n: PCCC Application Version'
  tag fix_id: 'F-16219r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Compromise of the supported communications or the supporting network.'
  tag responsibility: 'Information Assurance Officer'
end
