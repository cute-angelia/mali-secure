/** parseuri 解析结果 */
export interface ParsedUri {
  source:    string
  protocol:  string
  authority: string
  userInfo:  string
  user:      string
  password:  string
  host:      string
  port:      string
  relative:  string
  path:      string
  directory: string
  file:      string
  query:     string
  anchor:    string
  pathNames: string[]
  queryKey:  Record<string, string>
  ipv6uri?:  boolean
}

declare function parseuri(str: string): ParsedUri
export default parseuri
