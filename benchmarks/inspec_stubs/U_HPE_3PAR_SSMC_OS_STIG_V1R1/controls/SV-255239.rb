control 'SV-255239' do
  title 'SSMC must employ strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions.'
  desc 'If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system. The act of managing systems and applications includes the ability to access sensitive application information, such as system configuration details, diagnostic information, user information, and potentially sensitive application data.

Some maintenance and test tools are either standalone devices with their own operating systems or are applications bundled with an operating system.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.

'
  desc 'check', 'Verify that SSMC is configured to strong SSH ciphers to protect the integrity of remote access sessions by doing the following:

Log on to SSMC appliance as ssmcadmin via SSH, press "X" to escape to general bash shell from the TUI menu, and issue the following command:

$  sudo /ssmc/bin/config_security.sh -o cnsa_mode_appliance -a status

If the output does not read as "Appliance CNSA mode is enabled", this is a finding.'
  desc 'fix', 'Configure SSMC to use Strong SSH ciphers to protect the integrity of remote access sessions by doing the following:

1. Log on to the SSMC administrator console as "ssmcadmin". Press "X" to escape to general bash shell.

2. Execute the following command:

$  sudo /ssmc/bin/config_security.sh -o cnsa_mode_appliance -a enable -f'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC OS'
  tag check_id: 'C-58852r869865_chk'
  tag severity: 'medium'
  tag gid: 'V-255239'
  tag rid: 'SV-255239r869867_rule'
  tag stig_id: 'SSMC-OS-010040'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-58796r869866_fix'
  tag satisfies: ['SRG-OS-000125-GPOS-00065', 'SRG-OS-000396-GPOS-00176', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190', 'SRG-OS-000423-GPOS-00187']
  tag 'documentable'
  tag cci: ['CCI-000877', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-002450', 'CCI-003123']
  tag nist: ['MA-4 c', 'AC-17 (2)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)', 'SC-13 b', 'MA-4 (6)']
end
