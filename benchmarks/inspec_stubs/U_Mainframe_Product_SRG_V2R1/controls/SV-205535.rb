control 'SV-205535' do
  title 'The Mainframe Product must automatically terminate a user session after conditions, as defined in site security plan, are met or trigger events requiring session disconnect.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific application system functionality where the system owner, data owner, or organization requires additional assurance. Based on requirements and events specified by the data or application owner, the application developer must incorporate logic into the application that will provide a control mechanism that disconnects users upon the defined event trigger. The methods for incorporating this requirement will be determined and specified on a case by case basis during the application design and development stages."
  desc 'check', 'If the Mainframe Product has no data screen capability, this requirement is not applicable.

Determine whether the Mainframe Product has capability to terminate user sessions according to conditions as defined in site security plan and triggers. If it cannot, this is a finding.

Examine Configuration settings to determine whether the Mainframe Product is configured to automatically terminate sessions. If it is not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to automatically terminate a user session after any conditions as defined in site security plan or trigger requiring disconnect.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5801r299838_chk'
  tag severity: 'medium'
  tag gid: 'V-205535'
  tag rid: 'SV-205535r851303_rule'
  tag stig_id: 'SRG-APP-000295-MFP-000006'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-5801r299839_fix'
  tag 'documentable'
  tag legacy: ['SV-82607', 'V-68117']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
