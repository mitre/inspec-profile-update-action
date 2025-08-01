control 'SV-79687' do
  title 'The DataPower Gateway providing user access control intermediary services must retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the network. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law.

To establish acceptance of the application usage policy, a click-through banner at application logon is required. The network element must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'For an HTTPS application hosted on DataPower to display a landing page, the application designer will need to make that landing page available on the DataPower appliance or remotely accessible on a server. This landing page will be the page that the user sees, and the user will have to acknowledge this page before being redirected to the application/logon.

If the banner page does not load when first accessing an application, this is a finding.'
  desc 'fix', 'The application designer will create a service object in DataPower (e.g., Multi Protocol Gateway). As part of the object configuration, the application designer will create a Processing Policy object. The processing policy controls access to the Processing Rules of the application. 

The application designer will create a Processing Rule that allows the banner page to be displayed when a user accesses the application. The application designer will ensure that the banner page redirects the application user to the appropriate next step (e.g., logon page, application page, etc.) after the end user has accepted the terms of the agreement.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65825r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65197'
  tag rid: 'SV-79687r1_rule'
  tag stig_id: 'WSDP-AG-000012'
  tag gtitle: 'SRG-NET-000042-ALG-000023'
  tag fix_id: 'F-71137r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
