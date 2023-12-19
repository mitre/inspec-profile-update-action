control 'SV-233875' do
  title 'The Infoblox NIOS version must be at the appropriate version.'
  desc 'Each newer version of the name server software, especially the BIND software, generally is devoid of vulnerabilities found in earlier versions because it has design changes incorporated to address those vulnerabilities. These vulnerabilities have been exploited (i.e., some form of attack was launched), and sufficient information has been generated with respect to the nature of those exploits. 

It makes good business sense to run the latest version of name server software because theoretically, it is the safest version. However, even if the software is the latest version, it is not safe to run it in default mode. The security administrator must always configure the software to run in the recommended secure mode of operation after becoming familiar with the new security settings for the latest version.'
  desc 'check', 'Infoblox systems use a modified version of BIND DNS software, which adds features and addresses security issues outside of those provided by ISC. Infoblox systems are provided as a hardened appliance and do not allow user access or upgrading of any software components, including BIND. The Infoblox support portal and release notes are the authoritative sources to validate version and applicability of vulnerabilities. 

1. Verify the NIOS version by reviewing the "Grid, Upgrade" tab to show that all members are at the current version.  
2. Use the Infoblox support portal to obtain current version information. 

If the Infoblox NIOS version is not currently under support maintenance or is not at the current approved version level, this is a finding.'
  desc 'fix', 'Refer to the Infoblox NIOS Administrator Guide if necessary.  

1. Log on to the Infoblox support portal and download the current version of NIOS. 
2. Perform a Grid upgrade.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37060r611145_chk'
  tag severity: 'medium'
  tag gid: 'V-233875'
  tag rid: 'SV-233875r621666_rule'
  tag stig_id: 'IDNS-8X-400017'
  tag gtitle: 'SRG-APP-000516-DNS-000103'
  tag fix_id: 'F-37025r611146_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
