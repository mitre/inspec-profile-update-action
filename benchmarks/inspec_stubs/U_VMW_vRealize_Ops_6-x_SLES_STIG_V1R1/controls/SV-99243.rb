control 'SV-99243' do
  title 'The SLES for vRealize must terminate all sessions and network connections related to nonlocal maintenance when nonlocal maintenance is completed.'
  desc 'If a maintenance session or connection remains open after maintenance is completed, it may be hijacked by an attacker and used to compromise or damage the system.

Some maintenance and test tools are either standalone devices with their own operating systems or are applications bundled with an operating system.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.'
  desc 'check', 'Check for the existence of the "/etc/profile.d/tmout.sh" file:

# ls -al /etc/profile.d/tmout.sh

Check for the presence of the "TMOUT" variable:

# grep TMOUT /etc/profile.d/tmout.sh

The value of "TMOUT" should be set to "900" seconds (15 minutes).

If the file does not exist, or the "TMOUT" variable is not set to "900", this is a finding.'
  desc 'fix', 'Ensure the file exists and is owned by "root". If the files does not exist, use the following commands to create the file:

# touch /etc/profile.d/tmout.sh
# chown root:root /etc/profile.d/tmout.sh
# chmod 644 /etc/profile.d/tmout.sh

Edit the file "/etc/profile.d/tmout.sh", and add the following lines: 

TMOUT=900
readonly TMOUT
export TMOUT
mesg n 2>/dev/null'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88285r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88593'
  tag rid: 'SV-99243r1_rule'
  tag stig_id: 'VROM-SL-000740'
  tag gtitle: 'SRG-OS-000126-GPOS-00066'
  tag fix_id: 'F-95335r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end
