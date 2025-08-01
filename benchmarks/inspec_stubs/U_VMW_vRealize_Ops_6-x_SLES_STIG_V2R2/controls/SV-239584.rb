control 'SV-239584' do
  title 'The SLES for vRealize must protect audit tools from unauthorized deletion.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

SLES for vRealize systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has in order to make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', "The following command will list which audit files on the system where the ownership has been modified:

# rpm -V audit | grep '^.....U'

If there is output, this is a finding."
  desc 'fix', 'For each file that has the incorrect owner modification, alter the ownership of the file with the following command:

# chown <owner> <filename>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42817r662201_chk'
  tag severity: 'medium'
  tag gid: 'V-239584'
  tag rid: 'SV-239584r662203_rule'
  tag stig_id: 'VROM-SL-000890'
  tag gtitle: 'SRG-OS-000258-GPOS-00099'
  tag fix_id: 'F-42776r662202_fix'
  tag 'documentable'
  tag legacy: ['SV-99289', 'V-88639']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
