control 'SV-223586' do
  title 'IBM z/OS SMF recording options for the SSH daemon must be configured to write SMF records for all eligible events.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).

'
  desc 'check', 'Locate the SSH daemon configuration file which may be found in "/etc/ssh/" directory.

Alternately:

From UNIX System Services ISPF Shell, navigate to ribbon select tools.

Select option 1 - Work with Processes.

If SSH Daemon is not active, this is not a finding.

Examine SSH daemon configuration file. 

If ServerSMF is not coded with ServerSMF TYPE119_U83 or is commented out, this is a finding.'
  desc 'fix', 'Configure the SERVERSMF statement in the SSH Daemon configuration file to TYPE119_U83.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25259r504734_chk'
  tag severity: 'medium'
  tag gid: 'V-223586'
  tag rid: 'SV-223586r533198_rule'
  tag stig_id: 'ACF2-SH-000010'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-25247r504735_fix'
  tag satisfies: ['SRG-OS-000032-GPOS-00013', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag legacy: ['SV-106981', 'V-97877']
  tag cci: ['CCI-000067', 'CCI-002884']
  tag nist: ['AC-17 (1)', 'MA-4 (1) (a)']
end
