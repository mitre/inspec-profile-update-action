control 'SV-252641' do
  title "The IBM Aspera High-Speed Transfer Server must restrict Aspera transfer users to a limited part of the server's file system."
  desc "By restricting the transfer users to a limited part of the server's file system, this prevents unauthorized data transfers.
By default, all system users can establish a FASP connection and are only restricted by file permissions."
  desc 'check', %q(Verify the Aspera High-Speed Transfer Server restricts Aspera transfer users to a limited part of the server's file system.

Check that each user is restricted to a specific transfer folder with the following command:

Warning: If an invalid user/group name is entered, the asuserdata command will return results that may appear accurate. Ensure that the user/group name is valid and entered into the command correctly.

$ sudo /opt/aspera/bin/asuserdata -u <username> | grep absolute

canonical_absolute: "<specifictranferfolder>"
absolute: "<sepcifictransferfolder>"

If the transfer user's docroot is set to "<Empty String>" or is blank, this is a finding.)
  desc 'fix', %q(Configure the Aspera High-Speed Transfer Server to restrict Aspera transfer users to a limited part of the server's file system with the following command:

$ sudo /opt/aspera/bin/asconfigurator -x "set_user_data; user_name, <username>;canonical_absolute,<transferfolder>; absolute,<transferfolder>"

Restart the IBM Aspera Node service to activate the changes.

$ sudo systemctl restart asperanoded.service)
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56097r818091_chk'
  tag severity: 'medium'
  tag gid: 'V-252641'
  tag rid: 'SV-252641r818093_rule'
  tag stig_id: 'ASP4-TS-020250'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-56047r818092_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
