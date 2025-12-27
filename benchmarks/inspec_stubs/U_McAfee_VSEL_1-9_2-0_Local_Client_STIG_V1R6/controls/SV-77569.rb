control 'SV-77569' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be configured to find unknown program viruses.'
  desc 'Due to the ability of malware to mutate after infection, standard anti-virus signatures may not be able to catch new strains or variants of the malware. Typically, these strains and variants will share unique characteristics with others in their virus family. By using a generic signature to detect the shared characteristics, using wildcards where differences lie, the generic signature can detect viruses even if they are padded with extra, meaningless code. This method of detection is Heuristic detection.'
  desc 'check', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Scanning Options", verify the "Find unknown program viruses" check box is selected.

If the check box "Find unknown program viruses" is not selected, this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "heuristicAnalysis" nailsd.cfg"

If the response given is "nailsd.profile.OAS.heuristicAnalysis: false" or is "nailsd.profile.OAS.heuristicAnalysis: true" with a preceding #, this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "On-Access Settings".
Under "Anti-virus Scanning Options", select the "Find unknown program viruses" check box.

Click "Apply".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63831r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63079'
  tag rid: 'SV-77569r1_rule'
  tag stig_id: 'DTAVSEL-005'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-68997r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
