control 'SV-81027' do
  title 'The Juniper SRX Services Gateway must terminate a device management session after 10 minutes of inactivity, except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session. Quickly terminating an idle session also frees up resources. 

This requirement does not mean that the device terminates all sessions or network access; it only ends the inactive session.

User accounts, including the account of last resort must be assigned to a login class. Configure all login classes with an idle timeout value. Pre-defined classes do not support configurations, therefore should not be used for DoD implementations. The root account cannot be assigned to a login-class which is why it is critical that this account be secured in accordance with DoD policy.'
  desc 'check', 'Verify idle-timeout is set for 10 minutes.

[edit]
show system login

If a timeout value of 10 or less is not set for each class, this is a finding.'
  desc 'fix', 'Configure all login classes with an idle timeout value. 

[edit]
set system login-class <class name> idle-timeout 10

All users must be set to a login-class; however, to ensure that the CLI is set to a default timeout value, enter the following in operational mode: 

set cli idle-timeout 10'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67183r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66537'
  tag rid: 'SV-81027r1_rule'
  tag stig_id: 'JUSX-DM-000156'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-72613r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
