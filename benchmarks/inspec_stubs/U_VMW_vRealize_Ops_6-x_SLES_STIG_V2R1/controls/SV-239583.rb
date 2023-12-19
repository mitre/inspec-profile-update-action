control 'SV-239583' do
  title 'The SLES for vRealize must protect audit tools from unauthorized modification.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

SLES for vRealize systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has in order to make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', "The following command will list which audit files on the system where the group ownership has been modified:

# rpm -V audit | grep '^......G'

If there is output, this is a finding."
  desc 'fix', 'For each file that has the incorrect group modification, alter the group ownership of the file with the following command:

# chgrp <group> <filename>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42816r662198_chk'
  tag severity: 'medium'
  tag gid: 'V-239583'
  tag rid: 'SV-239583r662200_rule'
  tag stig_id: 'VROM-SL-000885'
  tag gtitle: 'SRG-OS-000257-GPOS-00098'
  tag fix_id: 'F-42775r662199_fix'
  tag 'documentable'
  tag legacy: ['SV-99287', 'V-88637']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
