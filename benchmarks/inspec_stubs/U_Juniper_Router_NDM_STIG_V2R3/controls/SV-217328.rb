control 'SV-217328' do
  title 'The Juniper router must be configured to terminate all network connections associated with device management after five minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Review the router configuration to verify that all login classes have the idle-timeout value to five minutes or less as shown in the following example:

system {
    …
    …
    …
    }
    login {
        class ADMIN {
            idle-timeout 5;
            permissions admin-control;
        }
    }

If the router is not configured to terminate all network connections associated with a device management after five minutes of inactivity, this is a finding.'
  desc 'fix', 'Set the idle timeout value to five minutes or less on all configured login classes as shown in the example below.

[edit system login]
set class ADMIN idle-timeout 5'
  impact 0.7
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18555r916307_chk'
  tag severity: 'high'
  tag gid: 'V-217328'
  tag rid: 'SV-217328r916309_rule'
  tag stig_id: 'JUNI-ND-000710'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-18553r916308_fix'
  tag 'documentable'
  tag legacy: ['SV-101241', 'V-91141']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
