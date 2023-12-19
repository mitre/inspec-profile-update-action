control 'SV-223247' do
  title 'SharePoint must allow designated organizational personnel to select which auditable events are to be audited by specific components of the system.'
  desc 'Audit records can be generated from various components within the information system, such as network interfaces, hard disks, modems, etc. From an application perspective, certain specific application functionalities may be audited as well.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records (i.e., auditable events, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked).

Organizations may define the organizational personnel accountable for determining which application components shall provide auditable events.'
  desc 'check', %q(Review the SharePoint server configuration to ensure designated organizational personnel are allowed to select which auditable events are to be audited by specific components of the system.

Navigate to Central Administration.

Click "Monitoring".

Click "Configure Diagnostic Logging".

Validate that the selected event categories and trace levels match those defined by the organization's system security plan.

Remember that a base set of events are always audited.

If the selected event categories/trace levels are inconsistent with those defined in the organization's system security plan, this is a finding.)
  desc 'fix', %q(Configure the SharePoint server configuration to allow designated organizational personnel to select which auditable events are to be audited by specific components of the system.

Navigate to Central Administration.

Click "Monitoring".

Click "Configure Diagnostic Logging".

Select the event categories and trace levels to match those defined by the organization's system security plan.

Remember that a base set of events is always audited.

Click "Ok".)
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint Server 2013'
  tag check_id: 'C-24920r430801_chk'
  tag severity: 'medium'
  tag gid: 'V-223247'
  tag rid: 'SV-223247r612235_rule'
  tag stig_id: 'SP13-00-000055'
  tag gtitle: 'SRG-APP-000090'
  tag fix_id: 'F-24908r430802_fix'
  tag 'documentable'
  tag legacy: ['V-59953', 'SV-74383']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
