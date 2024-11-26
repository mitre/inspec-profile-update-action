control 'SV-253948' do
  title 'The Juniper EX switch must be configured to disable non-essential capabilities.'
  desc 'A compromised switch introduces risk to the entire network infrastructure as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each switch is to enable only the capabilities required for operation.'
  desc 'check', 'Review the switch configuration and verify the switch does not have an unnecessary or non-secure services enabled. For example, the following directives should not be in the configuration (deleted) or, if present, must be disabled (inactive):

Verify the following commands are not present:
[edit system services]
finger;
ftp;
rlogin;
telnet;
xnm-clear-text;
tftp;
rest {
    http;
}
web-management {
    http;
    https;
}
Note: If the services listed above are marked "inactive", they are not enabled. For example, although the FTP stanza is present in the following snippet, it is disabled (inactive):
[edit system services]
inactive: ftp;

Because J-Web was not included in the FIPS certification, verify the web-management process is disabled.
[edit system services]
web-management disable;

If any unnecessary services are enabled, this is a finding.'
  desc 'fix', 'Disable the following services:

If present, delete the following directives:
delete system services finger
delete system services ftp
delete system services rlogin
delete system services telnet
delete system services xnm-clear-text
delete system services tftp
delete system services rest http
delete system services web-management

Disable the web-management process:
set system processes web-management disable'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57400r843875_chk'
  tag severity: 'high'
  tag gid: 'V-253948'
  tag rid: 'SV-253948r843877_rule'
  tag stig_id: 'JUEX-L2-000010'
  tag gtitle: 'SRG-NET-000131-L2S-000014'
  tag fix_id: 'F-57351r843876_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
