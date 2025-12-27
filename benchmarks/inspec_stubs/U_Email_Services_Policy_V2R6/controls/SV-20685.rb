control 'SV-20685' do
  title 'Email Acceptable Use Policy must contain required elements.'
  desc 'Email is only as secure as the recipient, which is ultimately the person who is receiving messages. Also to consider, the surest way to prevent SPAM and other malware from entering the email message transport path is by using secure IA measures at the point of origin. Here again, this is ultimately a person, who is sending messages. 

Email Acceptable Use Policy statements must include user education and expectations, as well as penalties and legal ramifications surrounding noncompliance. Examples of elements may include such items as classification and sensitivity labeling, undesirable message recognition such as for SPAM, Phishing, or bogus certificates. 

There should also be process information, such as the Email Acceptable Use Policy location, review frequency, email services offered (Outlook, web based email), and email services forbidden (such as access via alternate email products). Users may also need to know other useful information, such as mailbox size quotas, attachment limitations, and procedural steps for making help desk requests. 

Email tools, rules, and alerts descriptions plus official formats of email based announcements that may originate from the Email Administration team should be documented to prevent users being fooled or compromised by social engineering exploits. It may also be advantageous to have an ‘official’ method of communicating, enabling users to then recognize non-authentic requests and report them.'
  desc 'check', 'Access the EDSP documentation that describes the Email Acceptable Use Policy elements. 
Included should be elements such as the following:
  
User education 
User expectations 
Penalties for non-conformance
Legal ramifications
Classification labeling
SPAM and Phishing recognition
Bogus certificates
Review frequency
Services offered or not offered
Message and attachment size quotas
Help desk and other support information 

If the Email Acceptable Use Policy contains required elements, this is not a finding.'
  desc 'fix', 'Revise or supplement the Email Acceptable Use Policy so it contains the required elements. Document the email acceptable use policy elements in the EDSP.'
  impact 0.3
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22540r3_chk'
  tag severity: 'low'
  tag gid: 'V-18886'
  tag rid: 'SV-20685r3_rule'
  tag stig_id: 'EMG0-092 EMail'
  tag gtitle: 'EMG0-092 Acceptable Use Policy Required Elements'
  tag fix_id: 'F-19582r3_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'PRRB-1'
end
