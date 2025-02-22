control 'SV-32788' do
  title 'The web server password(s) must be entrusted to the SA or Web Manager.'
  desc 'Normally, a service account is established for the web server. This is because a privileged account is not desirable and the server is designed to run for long uninterrupted periods of time. The SA or Web Manager will need password access to the web server to restart the service in the event of an emergency as the web server is not to restart automatically after an unscheduled interruption.  If the password is not entrusted to an SA or web manager the ability to ensure the availability of the web server is compromised.'
  desc 'check', 'The reviewer should make a note of the name of the account being used for the web service. This
information may be needed later in the SRR. There may also be other server services running related to the web server in support of a particular web application, these passwords must be entrusted to the SA or Web Manager as well.
Query the SA or Web Manager to determine if they have the web service password(s).

If the web services password(s) are not entrusted to the SA or Web Manager, this is a finding.

NOTE: For installations that run as a service, or without a password, the SA or Web Manager having an Admin account on the system would meet the intent of this check.'
  desc 'fix', 'Ensure the SA or Web Manager are entrusted with the web service(s) password.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-3751r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2232'
  tag rid: 'SV-32788r1_rule'
  tag stig_id: 'WG050 A22'
  tag gtitle: 'WG050'
  tag fix_id: 'F-2281r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Web Administrator']
end
