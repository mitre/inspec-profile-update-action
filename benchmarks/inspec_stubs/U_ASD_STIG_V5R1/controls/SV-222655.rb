control 'SV-222655' do
  title 'Threat models must be documented and reviewed for each application release and updated as required by design and functionality changes or when new threats are discovered.'
  desc 'Threat modeling is an approach for analyzing the security of an application. It is a structured approach that enables you to identify, quantify, and address the security risks associated with an application. Threat modeling is not an approach to reviewing code, but it does complement the security code review process.

Threat modeling can optimize application security by identifying objectives and vulnerabilities, and then defining countermeasures to prevent, or mitigate the effects of, threats to the system.

The lack of threat modeling will potentially leave unidentified threats for attackers to utilize to gain access to the application. To execute a threat model you should do the following:

- Decompose the Application. The first step in the threat modeling process is gaining an understanding of the application and how it interacts with external entities. This includes identifying application components such as web server, application server, database server and languages used by the application. It also includes identifying network connections and the means utilized to access the application.

- Determine and rank threats. Use a threat categorization methodology to understand the different threat categories.
E.g., Auditing, authentication, configuration management and data protection. The goal of the threat categorization is to help identify threats both from the attacker perspective and the defensive perspective.

- Determine countermeasures and mitigation. A lack of protection against a threat might indicate a vulnerability whose risk exposure could be mitigated with the implementation of a countermeasure.

Countermeasures could include using application firewalls, IDS/IPS to block or identify known attacks against the architecture and alarming on audit log events.

Refer to the OWASP website for additional details on application threat modeling.

https://www.owasp.org/index.php/Application_Threat_Modeling'
  desc 'check', 'This requirement is meant to apply to developers or organizations that are doing application development work.

If the organization operating the application is not doing the development or is not managing the development of the application, the requirement is not applicable.

Review the threat model document and identify the following sections are present:

- Identified threats
- Potential vulnerabilities
- Counter measures taken
- Potential mitigations
- Mitigations selected based on risk analysis

Review the identified threats, vulnerabilities, and countermeasures.
Countermeasures could include implementing application firewalls or IDS/IPS and configuring certain IDS filters.

Review the application documentation.
Verify the architecture and components of the application match with the components in the threat model document.
Verify identified threats and vulnerabilities are addressed or mitigated and the ISSO and ISSM have reviewed and approved the document.

If the described threat model documentation does not exist, this is a finding.'
  desc 'fix', 'Establish and maintain threat models and review for each application release and when new threats are discovered. Identify potential mitigations to identified threats. Verify mitigations are implemented to threats based on their risk analysis.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24325r493873_chk'
  tag severity: 'medium'
  tag gid: 'V-222655'
  tag rid: 'SV-222655r508029_rule'
  tag stig_id: 'APSC-DV-003230'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24314r493874_fix'
  tag 'documentable'
  tag legacy: ['SV-85011', 'V-70389']
  tag cci: ['CCI-003256', 'CCI-000366']
  tag nist: ['SA-15 (4)', 'CM-6 b']
end
