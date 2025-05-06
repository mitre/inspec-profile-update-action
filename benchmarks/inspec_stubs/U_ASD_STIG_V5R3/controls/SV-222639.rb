control 'SV-222639' do
  title 'Back-up copies of the application software or source code must be stored in a fire-rated container or stored separately (offsite).'
  desc 'Application developers and application administrators must take steps to ensure continuity of development effort and operations should a disaster strike.  

Steps include protecting back-up copies of development code and application software.

Improper storage of the back-up copies can result in extended outages of the information system in the event of a fire or other situation that results in destruction of the back-up as well as the operating copy.

To address this risk, copies of application software and application source code must be stored in a fire-rated container or separately (offsite) from the operational or development environments.'
  desc 'check', 'When reviewing a COTS or GOTS application, verify that a back-up copy of the software is stored in a fire rated container or is stored separately (offsite) from the operational environment.

Determine if application development is done in-house. 

If application development occurs in-house and source code is available, verify a back-up copy of the source code is kept in a fire-rated container or stored offsite from the development environment.

If back-up copies of the application software or source code are not stored in a fire-rated container or stored separately (offsite) from their respective environments, this is a finding.'
  desc 'fix', 'Store a back-up copy of the application software and source code in a fire-rated container or store it separately (offsite) from their respective environments.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24309r493825_chk'
  tag severity: 'medium'
  tag gid: 'V-222639'
  tag rid: 'SV-222639r879887_rule'
  tag stig_id: 'APSC-DV-003080'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24298r493826_fix'
  tag 'documentable'
  tag legacy: ['SV-84979', 'V-70357']
  tag cci: ['CCI-000540']
  tag nist: ['CP-9 (d)']
end
