control 'SV-252645' do
  title 'The IBM Aspera High-Speed Transfer Server must set the default docroot to an empty folder.'
  desc 'By restricting the default document root for the Aspera HSTS, this allows for explicit access to be defined on a per user basis.
By default, all system users can establish a FASP connection and are only restricted by file permissions.'
  desc 'check', 'Verify the Aspera High-Speed Transfer Server set the default docroot to an empty folder.

Check that the default docroot points to an empty folder with the following command:

$ sudo /opt/aspera/bin/asuserdata -a | grep absolute

canonical_absolute: "<someemptyfolder>"
absolute: "<someemptyfolder>"

If the default docroot is set to "<Empty String>", this is a finding.

Review the default docroot file path from the previous command to ensure it is empty.

$ sudo find <somefilepath> -maxdepth 0 -empty -exec echo {} is empty. \\;

<somefilepath> is empty.

If the command does not return "<somefilepath> is empty.", this is a finding.'
  desc 'fix', 'Configure the Aspera High-Speed Transfer Server to set the default docroot to an empty folder with the following command:

$ sudo /opt/aspera/bin/asconfigurator -x "set_node_data;canonical_absolute,<someemptyfolder>; absolute,<someemptyfolder>"

Restart the IBM Aspera Node service to activate the changes.

$ sudo systemctl restart asperanoded.service'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56101r818103_chk'
  tag severity: 'medium'
  tag gid: 'V-252645'
  tag rid: 'SV-252645r818105_rule'
  tag stig_id: 'ASP4-TS-020290'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-56051r818104_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
