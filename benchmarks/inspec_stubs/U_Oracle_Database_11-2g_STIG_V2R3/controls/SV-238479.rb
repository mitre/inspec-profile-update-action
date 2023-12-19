control 'SV-238479' do
  title 'The DBMS must support taking organization-defined list of least disruptive actions to terminate suspicious events.'
  desc 'System availability is a key tenet of system security. Organizations need to have the flexibility to be able to define the automated actions taken in response to an identified incident. This includes being able to define a least disruptive action the application takes to terminate suspicious events. A least disruptive action may include initiating a request for human response rather than blocking traffic or disrupting system operation.

In order to preserve availability, it is important for the DBMS to terminate suspicious events with the least disruptive action possible.  If suspicious events are not terminated, an attacker may gain entry into the system; however, if the system overreacts to a suspicious event and takes an overly disruptive action, a Denial of Service (DoS) may occur.'
  desc 'check', "Obtain the CC/S/A/FA's list of suspicious event types and the actions to be taken in response, ordered from least disruptive to last resort.  If the list does not exist, this is a finding.

For each event type in the list, review the measures in place in the DBMS/database configuration that are designed to detect and/or counter the event.  (Alerting an administrator or operator to the problem is a valid measure.)  

If, for any event type defined in the list, no means of detecting the event exists, this is a finding.

For each event type where an automatic countermeasure is defined, verify that its implementation is congruent with the list of defined actions.  If not, this is a finding.

Verify that administrators/operators are familiar with the list and the notification mechanism and are equipped to follow the instructions in the list.  If not, this is a finding."
  desc 'fix', 'If the list does not exist, create it.

For any event type defined in the list where no means of detecting the event exists, either create the means of detection or modify the list.

For each event type where an automatic countermeasure is defined but its implementation differs from its description in the list, either modify the countermeasure or amend the list.

If any administrators/operators are unfamiliar with the list or the notification mechanism, train them.

If any administrators/operators are not equipped to follow the instructions in the list, provide them with the means to do so.

Ensure the list is incorporated into, or referenced by, the System Security Plan.

Note that Oracle Audit Vault and Oracle Database Vault are optional products that can be of considerable use in implementing active protection measures of this kind.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41690r667609_chk'
  tag severity: 'medium'
  tag gid: 'V-238479'
  tag rid: 'SV-238479r667611_rule'
  tag stig_id: 'O112-C2-020300'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-41649r667610_fix'
  tag 'documentable'
  tag legacy: ['V-52183', 'SV-66399']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
