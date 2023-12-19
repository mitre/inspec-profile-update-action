control 'SV-216315' do
  title 'The graphical login service provides the capability of logging into the system using an X-Windows type interface from the console. If graphical login access for the console is required, the service must be in local-only mode.'
  desc 'Externally accessible graphical desktop software may open the system to remote attacks.'
  desc 'check', 'Determine if the X11 server system is providing remote services on the network.

# svcprop -p options/tcp_listen svc:/application/x11/x11-server

If the output of the command is "true" and network access to graphical user login is not required, this is a finding.'
  desc 'fix', 'The System Administrator profile is required:

Configure the X11 server for local system only graphics access.

# pfexec svccfg -s svc:/application/x11/x11-server setprop options/tcp_listen=false'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17551r371033_chk'
  tag severity: 'medium'
  tag gid: 'V-216315'
  tag rid: 'SV-216315r603267_rule'
  tag stig_id: 'SOL-11.1-030010'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17549r371034_fix'
  tag 'documentable'
  tag legacy: ['SV-60801', 'V-47929']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
