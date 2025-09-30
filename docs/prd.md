# PRD: TLSXtractor

## 1. Product overview

### 1.1 Document title and version

- **Title**: TLSXtractor
- **Version**: 1.0

### 1.2 Product summary

TLSXtractor is a specialized network reconnaissance tool designed to extract domain names and certificate information from TLS handshakes during mass scanning operations. The tool enables security professionals and network administrators to systematically enumerate domain assets across IP ranges by capturing Server Name Indication (SNI) and Subject Alternative Names (SAN) from TLS certificates.

The application supports multiple input modes including IP lists, CIDR notation, URLs, and hostnames, providing flexibility for different reconnaissance scenarios. It performs automated TLS negotiations at scale, capturing hostname information during the handshake process and exporting structured data in JSON format.

Built with performance and reliability in mind, TLSXtractor implements multi-threaded execution, rate limiting, retry mechanisms, and configurable timeouts to ensure efficient and responsible scanning operations. The tool is particularly valuable for asset discovery, attack surface mapping, and infrastructure enumeration during security assessments.

## 2. Goals

### 2.1 Business goals

- Provide security teams with efficient tooling for domain enumeration and asset discovery
- Reduce time required for reconnaissance phases during security assessments
- Enable comprehensive attack surface mapping for enterprise networks
- Support compliance and security auditing requirements for infrastructure visibility
- Differentiate in the security tooling market with high-performance TLS scanning capabilities

### 2.2 User goals

- Quickly enumerate all domains associated with a given IP range or CIDR block
- Discover hidden subdomains and alternative domain names through certificate SAN inspection
- Automate the collection of SNI and certificate data during large-scale scans
- Export results in a structured, machine-readable format for further analysis
- Minimize scan time while maintaining accuracy and avoiding rate-limiting issues
- Integrate TLS enumeration data into broader security assessment workflows

### 2.3 Non-goals

- We do not intend to provide full SSL/TLS certificate validation or security analysis
- We will not implement active exploitation or vulnerability scanning features
- We are not building a certificate monitoring or alerting system
- We will not include web application fingerprinting beyond TLS-level information
- We are not creating a user interface or web dashboard (command-line only)
- We will not store historical scan data or implement a database backend

## 3. User personas

### 3.1 Key user types

- Penetration testers and security consultants
- Security operations center (SOC) analysts
- Network administrators and infrastructure teams
- Bug bounty hunters
- Security researchers
- Red team operators

### 3.2 Basic persona details

- **Penetration testers**: Security professionals conducting authorized assessments who need to map client infrastructure and identify all domains in scope before testing
- **SOC analysts**: Security monitoring personnel performing regular asset discovery to maintain accurate inventory of organizational attack surface
- **Network administrators**: Infrastructure teams validating certificate deployments and identifying misconfigured or unauthorized services across their networks
- **Bug bounty hunters**: Independent security researchers searching for subdomain takeover vulnerabilities and undocumented endpoints on target programs
- **Security researchers**: Analysts conducting large-scale internet surveys and threat intelligence gathering on specific IP ranges or autonomous systems
- **Red team operators**: Offensive security professionals performing reconnaissance during simulated attack scenarios to identify targets and pivot points

### 3.3 Role-based access

- **System administrator**: Has full access to run the tool, configure parameters, and access all output files. Can execute scans against any target (subject to authorization and legal constraints). Responsible for managing rate limits and ensuring responsible use.
- **Operator**: Can execute pre-configured scans with limited parameter modification. Can access scan results but may have restrictions on target selection. Typically operates within defined scope boundaries.
- **Analyst**: Read-only access to scan results and output files. Can analyze exported JSON data but cannot initiate new scans. Uses results for threat intelligence and security analysis.

## 4. Functional requirements

### IP range scanning (Priority: High)

- Accept IP addresses, IP lists, and CIDR notation as input
- Support both IPv4 and IPv6 addresses
- Parse and validate input formats before scanning
- Handle large IP ranges efficiently with batching

### TLS handshake execution (Priority: High)

- Initiate TLS connections to specified targets on configurable ports (default: 443)
- Capture Server Name Indication (SNI) during the ClientHello phase
- Complete enough of the handshake to receive the server certificate
- Support multiple TLS versions (TLS 1.0, 1.1, 1.2, 1.3)
- Handle various cipher suites and connection scenarios

### Certificate data extraction (Priority: High)

- Parse X.509 certificates received during TLS handshakes
- Extract Subject Alternative Names (SAN) from certificate extensions
- Capture Common Name (CN) from certificate subject
- Record certificate validity periods and issuer information
- Handle malformed or unusual certificates gracefully

### URL and hostname processing (Priority: High)

- Accept input files containing URLs and hostnames
- Perform DNS resolution to obtain IP addresses for hostnames
- Extract hostname information from URLs
- Associate discovered IP addresses with their corresponding hostnames
- Handle DNS failures and unresolvable hostnames

### Multi-mode operation (Priority: High)

- Support "IP scan mode" for scanning IP ranges and capturing domains
- Support "URL/hostname mode" for resolving URLs to IPs and capturing SNI
- Dynamically adjust output format based on operation mode
- Allow mode selection via command-line parameters

### JSON output generation (Priority: High)

- Export all results in well-formed JSON format
- Structure output differently based on scan mode (IP-to-domains vs URL-to-IPs)
- Include metadata such as scan timestamp, parameters used, and statistics
- Support output to file or stdout
- Ensure JSON is properly formatted and parseable

### Performance and scalability (Priority: High)

- Implement multi-threaded or asynchronous execution for concurrent connections
- Support configurable thread/worker pool sizes
- Optimize for scanning thousands of IPs in reasonable time
- Minimize memory footprint during large scans
- Provide progress indicators during long-running operations

### Rate limiting and retry logic (Priority: Medium)

- Implement configurable rate limiting to avoid overwhelming targets or networks
- Support delays between connection attempts
- Automatically retry failed connections with exponential backoff
- Configure maximum retry attempts
- Log retry attempts and failures for troubleshooting

### Timeout and error handling (Priority: Medium)

- Implement configurable connection timeouts
- Handle network errors gracefully without crashing
- Support TLS handshake timeouts
- Log errors with sufficient detail for debugging
- Continue scanning on individual failures without stopping entire operation

### Logging and verbosity (Priority: Medium)

- Provide multiple logging levels (error, warning, info, debug)
- Output scan progress and statistics during execution
- Log failures, timeouts, and retry attempts
- Support logging to file and/or console
- Include timestamps in all log entries

### Input validation and security (Priority: Medium)

- Validate all input parameters before execution
- Prevent scanning of private IP ranges unless explicitly allowed
- Warn users about scanning large ranges
- Implement sanity checks on CIDR notation and IP formats
- Sanitize inputs to prevent injection attacks

### Configuration management (Priority: Low)

- Support command-line arguments for all major parameters
- Allow configuration via config file for complex setups
- Provide sensible defaults for common use cases
- Document all configuration options clearly
- Support environment variables for certain settings

## 5. User experience

### 5.1 Entry points & first-time user flow

- Users install the tool via package manager, binary download, or source compilation
- First-time users access help documentation via `--help` flag to understand available options
- Users prepare input data (IP list file, CIDR notation, or URL file)
- Users execute a test scan on a small range to verify functionality
- Users review JSON output to understand data structure before running large scans

### 5.2 Core experience

- **Prepare input data**: Users create or identify their target list (IP ranges, CIDR blocks, or URL file). The tool should provide clear examples in documentation showing expected input formats.
- **Execute scan**: Users run the command with appropriate flags (e.g., `tlsxtractor --cidr 192.168.1.0/24 --output results.json`). The tool displays a clear progress indicator showing scan velocity and estimated completion time.
- **Monitor progress**: During execution, users see real-time updates on successful connections, domains discovered, and any errors encountered. Progress information is concise and not overwhelming.
- **Handle completion**: Upon completion, the tool displays summary statistics (total IPs scanned, unique domains found, success rate) and confirms output file location.
- **Review results**: Users open the JSON output file to analyze discovered domains, SNI information, and certificate data. The JSON structure is intuitive with clear field names.

### 5.3 Advanced features & edge cases

- Handle rate-limited responses from target networks by automatically adjusting scan speed
- Support resuming interrupted scans from checkpoint data
- Detect and handle honeypots or IDS systems that may block scanning
- Process mixed input (both IPv4 and IPv6 in same scan)
- Handle targets with multiple TLS services on different ports
- Deal with servers that require SNI to respond properly
- Process wildcard certificates and extract meaningful domain patterns
- Handle international domain names (IDN) correctly
- Support scanning through SOCKS proxies for anonymity or network routing

### 5.4 UI/UX highlights

- Clean, minimal command-line interface with intuitive flags and parameters
- Helpful error messages that suggest corrective actions
- Progress bars or percentage indicators for long-running scans
- Color-coded console output (if terminal supports it) for better readability
- Quiet mode for scripting and automation use cases
- Summary statistics prominently displayed at scan completion
- Clear distinction between warnings (non-fatal) and errors (require attention)
- Examples provided in `--help` output for common use cases

## 6. Narrative

Marcus is a penetration tester conducting a security assessment for a client with a complex infrastructure spanning multiple data centers. He needs to identify all domains and subdomains associated with the client's IP ranges to ensure comprehensive testing coverage. Marcus discovers TLSXtractor and uses it to scan the provided CIDR blocks, automatically capturing SNI information and certificate SANs from thousands of IPs. Within minutes, he has a complete JSON export of all discovered domains, including several previously unknown subdomains that the client wasn't aware of. This automated reconnaissance saves Marcus hours of manual work and ensures he hasn't missed any assets, allowing him to focus on actual security testing rather than tedious enumeration tasks.

## 7. Success metrics

### 7.1 User-centric metrics

- Time saved compared to manual domain enumeration methods (target: 80% reduction)
- Number of previously unknown domains discovered per scan
- User-reported accuracy rate of domain discovery (target: 95%+)
- Tool adoption rate among security professionals and teams
- User satisfaction score based on ease of use and reliability
- Frequency of tool usage in typical security workflows

### 7.2 Business metrics

- Market share within security reconnaissance tooling category
- Number of active installations and users
- Community contributions and pull requests (for open source version)
- Integration into commercial security platforms
- Citation rate in security research papers and blog posts
- Training and certification course inclusions

### 7.3 Technical metrics

- Time to scan per 1,000 IPs (target: under 5 minutes with 10 threads)
- Domain resolution success rate (target: 90%+ for online hosts)
- Number of unique domains found per IP range (baseline measurement)
- Connection success rate (percentage of attempted connections that complete)
- Memory usage during large scans (target: under 500MB for 100K IP scan)
- CPU utilization efficiency across available cores
- Rate of false negatives (missed domains that exist)
- Tool crash rate or unexpected termination frequency

## 8. Technical considerations

### 8.1 Integration points

- DNS resolution libraries for hostname-to-IP translation
- TLS/SSL libraries (OpenSSL, BoringSSL, or native language implementations)
- JSON parsing and serialization libraries
- Command-line argument parsing frameworks
- Logging frameworks for structured output
- Potential integration with vulnerability scanners and security platforms
- Export compatibility with common SIEM and threat intelligence platforms
- API endpoints for programmatic access (future consideration)

### 8.2 Data storage & privacy

- All scan results stored locally in JSON files (no cloud transmission by default)
- No personally identifiable information (PII) collected from users
- Discovered domain names may be sensitive and should be handled securely
- Output files should have restricted permissions (600 or 640 on Unix systems)
- Consider encryption options for output files containing sensitive discovery data
- Avoid logging sensitive certificate details beyond necessary information
- Implement secure deletion options for temporary data
- Document data handling practices for compliance requirements

### 8.3 Scalability & performance

- Asynchronous I/O or multi-threading required to handle concurrent connections efficiently
- Connection pooling to manage socket resources effectively
- Memory-efficient data structures to handle large result sets
- Streaming JSON output for extremely large scans to avoid memory overflow
- Optimize DNS resolution with caching for repeated lookups
- Consider distributed scanning architecture for extremely large ranges (future enhancement)
- Profile CPU and memory usage under various load conditions
- Implement graceful degradation under resource constraints

### 8.4 Potential challenges

- Rate limiting and blocking by target networks or security devices
- Firewalls and IDS systems dropping TLS handshake attempts
- Legal and ethical considerations around scanning without proper authorization
- Handling diverse TLS implementations and edge cases across different servers
- Certificate parsing complexity with unusual or malformed certificates
- DNS resolution delays impacting overall scan performance
- IPv6 scanning complexities and routing issues
- Maintaining compatibility across different operating systems
- Keeping up with evolving TLS standards and deprecation of older versions
- False positives from honeypots or deceptive certificates
- Resource exhaustion on the scanning host during massive campaigns

## 9. Milestones & sequencing

### 9.1 Project estimate

- **Medium**: 2-4 weeks for core functionality with a skilled team
- Assumes use of existing TLS libraries and frameworks
- Includes basic testing and documentation
- Does not include extensive hardening or optimization

### 9.2 Team size & composition

- **Small team**: 2-3 total people
  - 1 senior software engineer (security/networking background)
  - 1 software engineer (focus on performance and concurrency)
  - Optional: 1 QA/security tester for validation

### 9.3 Suggested phases

- **Phase 1**: Core TLS scanning and SNI extraction (1 week)
  - Key deliverables: Basic TLS connection establishment, SNI capture, simple IP list input, console output of discovered domains
- **Phase 2**: Certificate parsing and multiple input modes (1 week)
  - Key deliverables: SAN extraction from certificates, CIDR support, URL/hostname input mode, DNS resolution functionality
- **Phase 3**: JSON export and performance optimization (3-5 days)
  - Key deliverables: Structured JSON output with mode-specific formatting, multi-threaded execution, basic progress indicators
- **Phase 4**: Reliability and production readiness (3-5 days)
  - Key deliverables: Rate limiting, retry logic, timeout handling, comprehensive error handling, logging system, input validation
- **Phase 5**: Documentation and testing (2-3 days)
  - Key deliverables: User documentation, usage examples, test suite, security review, deployment packaging

## 10. User stories

### 10.1 Scan IP range using CIDR notation

- **ID**: US-001
- **Description**: As a penetration tester, I want to scan an IP range specified in CIDR notation so that I can discover all domains associated with that network block.
- **Acceptance criteria**:
  - The tool accepts CIDR notation input (e.g., 192.168.1.0/24) via command-line parameter
  - All IPs within the CIDR range are scanned sequentially or concurrently
  - Discovered domains are captured from SNI and certificate SANs
  - Results are exported to JSON with IP-to-domains mapping
  - Invalid CIDR notation triggers a clear error message

### 10.2 Scan specific IP addresses from a list

- **ID**: US-002
- **Description**: As a security analyst, I want to provide a file containing a list of IP addresses so that I can scan specific targets without defining entire ranges.
- **Acceptance criteria**:
  - The tool accepts a file path containing one IP address per line
  - Both IPv4 and IPv6 addresses are supported
  - Comments and empty lines in the file are ignored
  - The tool validates each IP address before attempting connection
  - Invalid IPs are logged as warnings but don't stop the scan
  - Results include all domains discovered from each IP

### 10.3 Extract SNI from TLS handshake

- **ID**: US-003
- **Description**: As a network security specialist, I want to capture Server Name Indication (SNI) from TLS handshakes so that I can identify which hostnames clients are requesting from servers.
- **Acceptance criteria**:
  - The tool initiates TLS connections to target IPs on port 443 (or specified port)
  - SNI extension is captured from the ClientHello if present
  - The captured SNI value is stored in the results
  - Connections without SNI are handled without errors
  - Multiple SNI values (if present) are all captured

### 10.4 Extract Subject Alternative Names from certificates

- **ID**: US-004
- **Description**: As a security researcher, I want to extract Subject Alternative Names (SAN) from TLS certificates so that I can discover all domains covered by each certificate.
- **Acceptance criteria**:
  - The tool completes TLS handshake sufficiently to receive server certificate
  - X.509 certificate is parsed successfully
  - All SAN entries (DNS names) are extracted from the certificate extension
  - SAN values are stored in the output alongside SNI data
  - Certificates without SAN extension are handled gracefully
  - Other SAN types (IP addresses, email) are captured if present

### 10.5 Process URLs and extract hostnames

- **ID**: US-005
- **Description**: As a bug bounty hunter, I want to provide a file containing URLs so that the tool can extract hostnames, resolve them to IPs, and capture TLS information.
- **Acceptance criteria**:
  - The tool accepts a file containing one URL per line
  - Hostnames are extracted from URLs automatically
  - DNS resolution is performed to obtain IP addresses
  - TLS connections are made to resolved IPs with the hostname as SNI
  - Output JSON includes URL, hostname, resolved IP(s), and certificate data
  - Unresolvable hostnames are logged as warnings with the URL

### 10.6 Resolve hostnames to IP addresses

- **ID**: US-006
- **Description**: As a network administrator, I want the tool to perform DNS resolution for hostname inputs so that I can scan services by name without manually resolving IPs.
- **Acceptance criteria**:
  - The tool accepts standalone hostnames as input
  - DNS A and AAAA records are queried
  - All resolved IP addresses are included in the scan
  - DNS timeouts are handled with configurable timeout values
  - DNS resolution failures are logged but don't crash the tool
  - Results map hostnames to their discovered IP addresses

### 10.7 Export results in JSON format

- **ID**: US-007
- **Description**: As a security operations analyst, I want scan results exported in JSON format so that I can easily parse and integrate the data into my analysis tools.
- **Acceptance criteria**:
  - All scan results are exported as well-formed JSON
  - JSON structure includes metadata (scan time, parameters, version)
  - IP scan mode outputs IP-to-domains mapping
  - URL scan mode outputs URL-to-IP-to-domains mapping
  - JSON includes success/failure statistics for the scan
  - Output file is created even if scan is interrupted
  - JSON is human-readable with appropriate indentation

### 10.8 Configure multi-threaded execution

- **ID**: US-008
- **Description**: As a penetration tester scanning large networks, I want to configure the number of concurrent threads/workers so that I can optimize scan speed based on my system resources.
- **Acceptance criteria**:
  - The tool accepts a thread/worker count parameter (e.g., --threads 50)
  - Specified number of concurrent connections are maintained during scan
  - Thread count defaults to a sensible value (e.g., 10) if not specified
  - System resource usage scales appropriately with thread count
  - Results from all threads are safely aggregated into final output
  - Thread count validation prevents values that would crash the system

### 10.9 Implement rate limiting

- **ID**: US-009
- **Description**: As a responsible security professional, I want to configure rate limiting so that I don't overwhelm target networks or trigger defensive measures.
- **Acceptance criteria**:
  - The tool accepts a requests-per-second or delay parameter
  - Connections are throttled to respect the specified rate
  - Rate limiting works correctly with multi-threaded execution
  - The tool displays current scanning rate during operation
  - Rate can be adjusted via command-line flag
  - Default rate is set to avoid common rate-limiting thresholds

### 10.10 Retry failed connections

- **ID**: US-010
- **Description**: As a security tester dealing with unreliable networks, I want failed connections to be automatically retried so that temporary issues don't result in missed data.
- **Acceptance criteria**:
  - The tool automatically retries failed connections up to a configurable maximum
  - Exponential backoff is applied between retry attempts
  - Connection timeout errors trigger retries
  - Network unreachable errors trigger retries
  - Maximum retry count is configurable (default: 3)
  - Retry attempts are logged at debug level
  - Permanently failed hosts are marked as failed in the output

### 10.11 Handle connection timeouts

- **ID**: US-011
- **Description**: As a user scanning diverse networks, I want configurable connection timeouts so that slow or unresponsive hosts don't block the entire scan.
- **Acceptance criteria**:
  - Connection timeout is configurable via command-line parameter (default: 5 seconds)
  - TLS handshake timeout is separately configurable (default: 10 seconds)
  - Timed-out connections are logged with the timeout reason
  - Timeout events don't crash the tool
  - Timeouts trigger retry logic if enabled
  - Timeout statistics are included in scan summary

### 10.12 Display scan progress

- **ID**: US-012
- **Description**: As a user running long scans, I want to see real-time progress updates so that I know the scan is working and can estimate completion time.
- **Acceptance criteria**:
  - Progress is displayed as percentage or progress bar
  - Current scanning rate (IPs per second) is shown
  - Number of domains discovered so far is displayed
  - Estimated time to completion is calculated and shown
  - Progress updates don't flood the console (update every 1-2 seconds)
  - Progress can be disabled with a quiet flag for scripting

### 10.13 Log errors and debugging information

- **ID**: US-013
- **Description**: As a user troubleshooting scan issues, I want detailed logging with multiple verbosity levels so that I can diagnose problems without being overwhelmed by information.
- **Acceptance criteria**:
  - The tool supports log levels: error, warning, info, debug
  - Default log level is info
  - Log level is configurable via command-line flag (e.g., --log-level debug)
  - All log entries include timestamps
  - Errors include helpful context (IP address, error type, etc.)
  - Logs can be written to file in addition to console
  - Debug level shows TLS handshake details

### 10.14 Validate input parameters

- **ID**: US-014
- **Description**: As a tool user, I want input validation to catch mistakes early so that I don't waste time on misconfigured scans.
- **Acceptance criteria**:
  - Invalid IP addresses are rejected with clear error messages
  - Invalid CIDR notation is rejected before scan starts
  - Conflicting parameters trigger warnings (e.g., IP list and CIDR both specified)
  - File paths are validated before scan begins
  - Port numbers are validated (1-65535)
  - Thread counts are validated to prevent system overload
  - Helpful suggestions are provided when validation fails

### 10.15 Support both IPv4 and IPv6

- **ID**: US-015
- **Description**: As a network administrator managing modern infrastructure, I want the tool to support both IPv4 and IPv6 addresses so that I can scan my entire network regardless of protocol version.
- **Acceptance criteria**:
  - IPv4 addresses are accepted in standard dotted notation
  - IPv6 addresses are accepted in standard colon notation
  - Mixed IPv4 and IPv6 scans are supported in a single execution
  - CIDR notation works for both IPv4 (/24) and IPv6 (/64)
  - TLS connections work correctly for both protocol versions
  - Output JSON clearly distinguishes IP version for each result

### 10.16 Scan custom ports

- **ID**: US-016
- **Description**: As a security professional, I want to specify custom ports for TLS scanning so that I can enumerate services running on non-standard ports.
- **Acceptance criteria**:
  - The tool accepts a port parameter (e.g., --port 8443)
  - Default port is 443 if not specified
  - Multiple ports can be specified for scanning
  - Each IP is scanned on all specified ports
  - Output includes the port number for each discovered domain
  - Invalid port numbers (outside 1-65535) are rejected

### 10.17 Handle certificate parsing errors

- **ID**: US-017
- **Description**: As a user scanning diverse networks, I want the tool to handle malformed or unusual certificates gracefully so that scan doesn't fail due to individual bad certificates.
- **Acceptance criteria**:
  - Certificate parsing errors are logged but don't crash the tool
  - Partial certificate data is extracted when possible
  - Self-signed certificates are processed normally
  - Expired certificates are processed (validity dates noted)
  - Certificates with unusual extensions are handled
  - Output indicates when certificate parsing partially failed
  - Scan continues to next target after certificate errors

### 10.18 Generate scan summary statistics

- **ID**: US-018
- **Description**: As a user completing a scan, I want to see summary statistics so that I can quickly assess the scan results and success rate.
- **Acceptance criteria**:
  - Total number of IPs/hosts scanned is displayed
  - Number of successful TLS connections is shown
  - Number of unique domains discovered is calculated and displayed
  - Connection success rate percentage is calculated
  - Total scan duration is reported
  - Average scan rate (IPs per second) is calculated
  - Summary is displayed on console and included in JSON output

### 10.19 Support quiet mode for automation

- **ID**: US-019
- **Description**: As a developer integrating the tool into automated workflows, I want a quiet mode that suppresses non-essential output so that only critical information is displayed.
- **Acceptance criteria**:
  - A --quiet or --silent flag suppresses progress and informational messages
  - Only errors and warnings are displayed in quiet mode
  - JSON output is still generated normally
  - Exit codes properly indicate success or failure
  - Quiet mode is documented in help output
  - Quiet mode can be combined with logging to file

### 10.20 Provide comprehensive help documentation

- **ID**: US-020
- **Description**: As a new user, I want comprehensive help documentation accessible via command-line so that I can understand how to use the tool without external resources.
- **Acceptance criteria**:
  - --help flag displays complete usage information
  - All command-line parameters are documented with descriptions
  - Examples are provided for common use cases
  - Input file format requirements are explained
  - Default values for all parameters are listed
  - Version information is accessible via --version flag

### 10.21 Handle interrupted scans gracefully

- **ID**: US-021
- **Description**: As a user who may need to stop a scan, I want the tool to handle interruption signals gracefully so that I don't lose all progress data.
- **Acceptance criteria**:
  - SIGINT (Ctrl+C) is caught and handled gracefully
  - Partial results are written to JSON output file before exit
  - A scan summary is displayed for completed portion
  - Active connections are closed cleanly
  - Exit code indicates interrupted status
  - Option to resume from checkpoint in future enhancement

### 10.22 Exclude private IP ranges

- **ID**: US-022
- **Description**: As a responsible security professional, I want the ability to exclude private/internal IP ranges so that I only scan internet-facing infrastructure.
- **Acceptance criteria**:
  - Private IP ranges (RFC 1918) can be automatically excluded
  - Exclusion is configurable via command-line flag
  - Warning is displayed when private IPs are detected in scan input
  - Option to force scanning of private ranges when needed
  - Localhost (127.0.0.0/8) is excluded by default
  - Link-local addresses are excluded by default

### 10.23 Support SNI-based virtual hosting

- **ID**: US-023
- **Description**: As a security researcher, I want the tool to properly set SNI during handshakes so that I can discover domains on servers using SNI-based virtual hosting.
- **Acceptance criteria**:
  - The tool sends appropriate SNI in ClientHello based on input mode
  - In URL/hostname mode, the hostname is used as SNI
  - In IP-only mode, a default or empty SNI is sent
  - Option to specify custom SNI value for testing
  - Servers requiring SNI respond properly
  - SNI value sent is logged in debug mode

### 10.24 Capture certificate validity information

- **ID**: US-024
- **Description**: As a network administrator, I want to capture certificate validity dates so that I can identify expired or soon-to-expire certificates during scanning.
- **Acceptance criteria**:
  - Certificate notBefore date is extracted and included in output
  - Certificate notAfter date is extracted and included in output
  - Dates are formatted in ISO 8601 format in JSON output
  - Expired certificates are flagged in the output
  - Certificates expiring soon (configurable threshold) are flagged
  - Self-signed status is captured and noted

### 10.25 Handle DNS resolution failures

- **ID**: US-025
- **Description**: As a user scanning URLs or hostnames, I want DNS resolution failures to be handled gracefully so that one unresolvable name doesn't stop my entire scan.
- **Acceptance criteria**:
  - DNS resolution failures are logged with the hostname
  - Failed resolutions don't crash the tool
  - The scan continues with remaining resolvable names
  - Failure statistics are included in scan summary
  - Option to retry DNS resolution with different nameservers
  - NXDOMAIN, timeout, and server failure are distinguished

### 10.26 Support output to stdout

- **ID**: US-026
- **Description**: As a user integrating the tool into pipelines, I want the option to output JSON to stdout so that I can pipe results directly to other commands.
- **Acceptance criteria**:
  - A flag (e.g., --output -) sends JSON to stdout instead of file
  - Progress and logging go to stderr when using stdout for JSON
  - JSON output to stdout is properly formatted
  - Option works correctly with quiet mode
  - Exit codes properly indicate success/failure
  - Large outputs are streamed efficiently

### 10.27 Detect and report scan rate

- **ID**: US-027
- **Description**: As a user monitoring scan performance, I want real-time scan rate information so that I can assess if my configuration is optimal.
- **Acceptance criteria**:
  - Current scan rate (IPs or hosts per second) is calculated
  - Scan rate is updated in real-time during execution
  - Average scan rate over entire scan is tracked
  - Peak scan rate is recorded and reported
  - Scan rate information is included in final summary
  - Rate fluctuations are smoothed for display (rolling average)

### 10.28 Support configuration file

- **ID**: US-028
- **Description**: As a user with complex scanning requirements, I want to specify parameters in a configuration file so that I don't need to type long command lines repeatedly.
- **Acceptance criteria**:
  - The tool accepts a config file path (e.g., --config scan.conf)
  - Config file supports all command-line parameters
  - Config file format is clearly documented (YAML, JSON, or INI)
  - Command-line parameters override config file values
  - Invalid config file triggers clear error message
  - Example config files are provided in documentation

### 10.29 Capture certificate issuer information

- **ID**: US-029
- **Description**: As a security analyst, I want to capture certificate issuer information so that I can identify certificate authorities used across my infrastructure.
- **Acceptance criteria**:
  - Certificate issuer Common Name is extracted
  - Issuer Organization is captured if present
  - Issuer Country is captured if present
  - Self-signed certificates are clearly identified
  - Issuer information is included in JSON output
  - Well-known CA names are normalized for consistency

### 10.30 Implement connection pooling

- **ID**: US-030
- **Description**: As a user scanning large ranges, I want efficient connection management so that the tool doesn't exhaust system resources or create performance bottlenecks.
- **Acceptance criteria**:
  - Socket connections are managed in an efficient pool
  - System file descriptor limits are respected
  - Connection pool size is configurable
  - Closed connections are properly cleaned up
  - Memory usage remains stable during long scans
  - Connection reuse is implemented where possible for efficiency
