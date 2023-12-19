control 'SV-248887' do
  title 'OL 8 must ignore IPv4 Internet Control Message Protocol (ICMP) redirect messages.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf"
  desc 'check', 'Verify OL 8 ignores IPv4 ICMP redirect messages.

Note: If IPv4 is disabled on the system, this requirement is Not Applicable.

Check the value of the "accept_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.all.accept_redirects

net.ipv4.conf.all.accept_redirects = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.all.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.accept_redirects = 0

If "net.ipv4.conf.all.accept_redirects" is not set to "0", is missing or commented out, this is a finding.

If results are returned from more than one file location, this is a finding.'
  desc 'fix', %q(Configure OL 8 to ignore IPv4 ICMP redirect messages with the following command:

$ sudo sysctl -w net.ipv4.conf.all.accept_redirects=0

If "0" is not the system's default value then add or update the following line in the appropriate file under "/etc/sysctl.d":

net.ipv4.conf.all.accept_redirects = 0)
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52321r818728_chk'
  tag severity: 'medium'
  tag gid: 'V-248887'
  tag rid: 'SV-248887r818729_rule'
  tag stig_id: 'OL08-00-040279'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52275r780226_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
