control 'SV-216881' do
  title 'The vCenter Server for Windows must enable Login banner for vSphere web client.'
  desc 'The required legal notice must be configured for the vCenter web client.'
  desc 'check', '1. Login to the Platform Services Controller web interface with administrator@vsphere.local from

https://<FQDN or IP of PSC>/psc

In an embedded deployment the Platform Services Controller host name or IP address is the same as the vCenter Server host name or IP address.

If you specified a different SSO domain during installation, log in as administrator@<mydomain>.

2. Browse to Single Sign-On >> Configuration.

3. Click the "Login Banner" tab, click the "Edit" button.

If selection boxes next to "Status" or "Checkbox Consent" are not checked or if the Message is not configured to the standard DoD User Agreement, this is a finding.

Note: Supplementary Information: DoD Logon Banner
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  desc 'fix', '1. Login to the Platform Services Controller web interface with administrator@vsphere.local from

https://<FQDN or IP of PSC>/psc

In an embedded deployment the Platform Services Controller host name or IP address is the same as the vCenter Server host name or IP address.

If you specified a different SSO domain during installation, log in as administrator@<mydomain>.

2. Browse to Single Sign-On >> Configuration.

3. Click the "Login Banner" tab, click the "Edit" button.

4. Check the box next to "Status".

5. Check the box next to "Checkbox Consent".

6. Configure the Title and Message to the standard DoD User Agreement'
  impact 0.3
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18112r366357_chk'
  tag severity: 'low'
  tag gid: 'V-216881'
  tag rid: 'SV-216881r612237_rule'
  tag stig_id: 'VCWN-65-000062'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18110r366358_fix'
  tag 'documentable'
  tag legacy: ['V-94827', 'SV-104657']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
