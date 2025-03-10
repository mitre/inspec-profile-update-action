control 'SV-240530' do
  title 'The SLES for vRealize audit system must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Determine if "/sbin/insmod" is audited:

# cat /etc/audit/audit.rules | grep "/sbin/insmod"

If the result does not start with "-w" and contain "-p x", this is a finding.'
  desc 'fix', 'Add the following to "/etc/audit/audit.rules" in order to capture kernel module loading and unloading events:

-w /sbin/insmod -p x

OR

# /etc/dodscript.sh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43763r671329_chk'
  tag severity: 'medium'
  tag gid: 'V-240530'
  tag rid: 'SV-240530r671331_rule'
  tag stig_id: 'VRAU-SL-001415'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag fix_id: 'F-43722r671330_fix'
  tag 'documentable'
  tag legacy: ['SV-100487', 'V-89837']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
