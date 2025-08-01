control 'SV-223548' do
  title 'IBM z/OS system administrators must develop an automated process to collect and retain SMF data.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Ask the system administrator if there is an automated process is in place to collect and retain all SMF data produced on the system.

If, based on the information provided, it can be determined that an automated process is in place to collect and retain all SMF data produced on the system, this is not a finding.

If it cannot be determined this process exists and is being adhered to, this is a finding.'
  desc 'fix', 'The ISSO will ensure that an automated process is in place to collect SMF data.

Review SMF data collection and retention processes. Verify processes are automatically started to dump SMF collection files immediately upon their becoming full.

To ensure that all SMF data is collected in a timely manner, and to reduce the risk of data loss, the site will ensure that automated mechanisms are in place to collect and retain all SMF data produced on the system. Dump the SMF files (MANx) in systems based on the following guidelines:

Dump each SMF file as it fills up during the normal course of daily processing.

- Dump all remaining SMF data at the end of each processing day, or 
- Establish a process using Audit logging.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25221r504683_chk'
  tag severity: 'medium'
  tag gid: 'V-223548'
  tag rid: 'SV-223548r853541_rule'
  tag stig_id: 'ACF2-OS-000120'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-25209r504684_fix'
  tag 'documentable'
  tag legacy: ['V-97801', 'SV-106905']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
