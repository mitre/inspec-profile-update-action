control 'SV-224103' do
  title 'The IBM z/OS UNIX Telnet server warning banner must be properly specified.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.'
  desc 'check', 'From the ISPF Command Shell enter:
OMVS
cat inetd.conf

If the otelnet startup command includes option "-h" this is a finding.'
  desc 'fix', 'The otelnetd startup command should not include the option "-h", where:

-h indicates that the logon banner should not be displayed.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25776r516708_chk'
  tag severity: 'medium'
  tag gid: 'V-224103'
  tag rid: 'SV-224103r877943_rule'
  tag stig_id: 'TSS0-UT-000050'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag fix_id: 'F-25764r516709_fix'
  tag 'documentable'
  tag legacy: ['V-98913', 'SV-108017']
  tag cci: ['CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
