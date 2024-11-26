control 'SV-7009' do
  title 'There is no restriction on where a MFD or a printer can be remotely managed.'
  desc 'Since unrestricted access to the MFD or printer for management is not required the restricting the management interface to specific IP addresses decreases the exposure of the system to malicious actions.  If the MFD or printer is compromised it could lead to a denial of service or a compromise of sensitive data.
The SA will ensure devices can only be remotely managed by SA’s or printer administrators from specific IPs (SA workstations and print spooler).'
  desc 'check', 'The reviewer will, with the assistance of the SA, verify that the MFD or printer can only be remotely managed by SA or printer administrator from specific IPs (SA workstations and print spooler).  Look for list that restricts the protocol used for administrative access to specific IP addresses.'
  desc 'fix', "Restrict access to the MFD's or printer's management function to a specific set of IP addresses.  If the device lacks this functionality use an ACL in a router, firewall or switch to restrict the access."
  impact 0.7
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-2984r1_chk'
  tag severity: 'high'
  tag gid: 'V-6784'
  tag rid: 'SV-7009r1_rule'
  tag stig_id: 'MFD02.005'
  tag gtitle: 'MFD or a printer can be managed from any IP'
  tag fix_id: 'F-6447r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCBP-1'
end
