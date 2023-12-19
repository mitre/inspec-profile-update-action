control 'SV-222643' do
  title 'The application must have the capability to mark sensitive/classified output when required.'
  desc 'Failure to properly mark output could result in a disclosure of sensitive or classified data which is an immediate loss in confidentiality.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Ask the application representative for the application’s classification guide. This guide should document the data elements and their classification.

Determine which application functions to examine, giving preference to report generation capabilities and the most common user transactions that involve sensitive data (FOUO, secret or above).

Log on to the application and perform these in sequence, printing output when applicable. The application representative’s assistance may be required to perform these steps. For each function, note whether the appropriate markings appear on the displayed and printed output. If a classification document does not exist, data must be marked at the highest classification of the system.

Appropriate markings for an application are as follows: For classified data, markings are required at a minimum at the top and the bottom of screens and reports.

For FOUO data, markings are required at a minimum of the bottom of the screen or report. In some cases, technology may prohibit the appropriate markings on printed documents. For example, in some cases, it is not possible to mark all pages top and bottom when a user prints from a browser. If this is the case, ask the application representative if user procedures exist for manually marking printed documents. If procedures do exist, examine the procedures to verify if the users were to follow the procedures the data would be marked correctly.

Ask how these procedures are distributed to the users.

If appropriate markings are not present within the application and it is technically possible to have the markings present, this is a finding.

If it is not technically feasible to meet the minimum marking requirement and no user procedures exist or if followed the procedures will result in incorrect markings, or the procedures are not readily available to users, this is a finding.

In any case of a finding, the finding details should specify which functions failed to produce the desired results.

After completing the test, destroy all printed output using the site’s preferred method for disposal. For example: utilizing a shredder or disposal in burn bags.'
  desc 'fix', 'Enable the application to adequately mark sensitive/classified output.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24313r493837_chk'
  tag severity: 'high'
  tag gid: 'V-222643'
  tag rid: 'SV-222643r879887_rule'
  tag stig_id: 'APSC-DV-003120'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24302r493838_fix'
  tag 'documentable'
  tag legacy: ['SV-84987', 'V-70365']
  tag cci: ['CCI-001010']
  tag nist: ['MP-3 a']
end
