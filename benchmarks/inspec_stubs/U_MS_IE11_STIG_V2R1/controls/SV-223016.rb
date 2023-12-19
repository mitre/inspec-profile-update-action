control 'SV-223016' do
  title 'Check for publishers certificate revocation must be enforced.'
  desc "Check for publisher's certificate revocation options should be enforced to ensure all PKI signed objects are validated.

"
  desc 'check', %q(If the system is on the SIPRNet, this requirement is NA.

Open Internet Explorer.
From the menu bar, select "Tools".
From the "Tools" drop-down menu, select "Internet Options". From the "Internet Options" window, select the "Advanced" tab, from the "Advanced" tab window, scroll down to the "Security" category, and verify the "Check for publisher's certificate revocation" box is selected.

Procedure: Use the Windows Registry Editor to navigate to the following key:
 HKCU\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing Criteria

If the value "State" is "REG_DWORD = 23C00", this is not a finding.)
  desc 'fix', %q(If the system is on the SIPRNet, this requirement is NA.

Open Internet Explorer.
From the menu bar, select "Tools".
From the "Tools" drop-down menu, select "Internet Options". From the "Internet Options" window, select the "Advanced" tab from the "Advanced" tab window, scroll down to the "Security" category, and select the "Check for publisher's certificate revocation" box.

Note: Manual entry in the registry key:

HKCU\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\Software Publishing for the value "State", set to "REG_DWORD = 23C00", may first be required.)
  impact 0.3
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24689r428598_chk'
  tag severity: 'low'
  tag gid: 'V-223016'
  tag rid: 'SV-223016r428600_rule'
  tag stig_id: 'DTBI018-IE11'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-24677r428599_fix'
  tag satisfies: ['SRG-APP-000605']
  tag 'documentable'
  tag legacy: ['SV-59341', 'V-46477']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
