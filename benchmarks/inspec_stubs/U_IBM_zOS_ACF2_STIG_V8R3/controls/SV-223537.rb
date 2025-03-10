control 'SV-223537' do
  title 'The IBM z/OS BPX.SMF resource must be properly configured.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Review the FACILITY resource class for BPX.SMF. 

If the ACF2 rules are as follows, this is not a finding.

BPX.SMF.119.94 – READ allowed for users running the ssh, sftp, or scp client commands.
BPX.SMF.119.96 – READ allowed for users running the scp or sftp-server server commands.
BPX.SMF.119.97 – READ allowed for users running the scp or sftp client commands.

The following profile grants the permitted users the authority to write or test for any SMF record being recorded. Access should be permitted as follows:
BPX.SMF – READ access only when documented and justified in Site Security Plan. Documentation should include a reason why a more specific profile is not acceptable.'
  desc 'fix', 'Configure Facility resource class for BPX.SMF as follows:
BPX.SMF.119.94 – READ allowed for users running the ssh, sftp, or scp client commands.
BPX.SMF.119.96 – READ allowed for users running the scp or sftp-server server commands.
BPX.SMF.119.97 – READ allowed for users running the scp or sftp client commands.

The following profile grants the permitted users the authority to write or test for any SMF record being recorded. Access should be permitted as follows:
BPX.SMF – READ access only when documented and justified in Site Security Plan. Documentation should include a reason why a more specific profile is not acceptable.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25210r767057_chk'
  tag severity: 'medium'
  tag gid: 'V-223537'
  tag rid: 'SV-223537r767058_rule'
  tag stig_id: 'ACF2-OS-000010'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-25198r504667_fix'
  tag 'documentable'
  tag legacy: ['V-97779', 'SV-106883']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
