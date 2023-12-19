control 'SV-239627' do
  title 'The SLES for vRealize audit system must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Determine if "/sbin/insmod" is audited:

# cat /etc/audit/audit.rules | grep "/sbin/insmod"

If the result does not start with "-w" and contain "-p x", this is a finding.'
  desc 'fix', 'Add the following to the "/etc/audit/audit.rules" file in order to capture kernel module loading and unloading events:

-w /sbin/insmod -p x

OR

# /etc/dodscript.sh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42860r662330_chk'
  tag severity: 'medium'
  tag gid: 'V-239627'
  tag rid: 'SV-239627r662332_rule'
  tag stig_id: 'VROM-SL-001390'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag fix_id: 'F-42819r662331_fix'
  tag 'documentable'
  tag legacy: ['SV-99375', 'V-88725']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
