package normalize

import (
		"sort"
			"strings"
				"unicode"

					"fahscan/pkg/types"
)

func Space(value string) string {
		return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

func Lower(value string) string {
		return strings.ToLower(Space(value))
}

func Slug(value string) string {
		value = Lower(value)
			var b strings.Builder
				lastDash := false
					for _, r := range value {
								switch {
								case unicode.IsLetter(r) || unicode.IsDigit(r):
												b.WriteRune(r)
															lastDash = false
								case !lastDash:
												b.WriteByte('-')
															lastDash = true
								}
							}
								return strings.Trim(b.String(), "-")
						}

						func Label(value string) string {
								value = Space(strings.ReplaceAll(value, "_", " "))
									if value == "" {
												return ""
									}
										parts := strings.Fields(value)
											for i, part := range parts {
														if isInitialism(part) {
																		parts[i] = strings.ToUpper(part)
																					continue
														}
																runes := []rune(strings.ToLower(part))
																		runes[0] = unicode.ToUpper(runes[0])
																				parts[i] = string(runes)
													}
														return strings.Join(parts, " ")
												}

												func ServiceKey(service types.Service) string {
														return strings.Join([]string{
																	intString(service.Port),
																			Lower(service.Protocol),
																					Lower(service.Service),
																							Lower(service.Product),
																									Lower(service.Version),
														}, "|")
												}

												func FindingKey(finding types.Finding) string {
														if finding.CVEID != "" {
																	return "cve|" + strings.ToUpper(Space(finding.CVEID))
														}
															return strings.Join([]string{
																		"finding",
																				Lower(finding.Title),
																						Lower(finding.Severity),
																								Lower(finding.Evidence),
															}, "|")
												}

												func TargetKey(target string) string {
														return Lower(strings.TrimSuffix(target, "."))
												}

												func UniqueStrings(values []string) []string {
														seen := map[string]string{}
															for _, value := range values {
																		key := Lower(value)
																				if key == "" {
																								continue
																				}
																						if _, ok := seen[key]; !ok {}
																				}
															}
												}
												}
															})
														}
												}
														})
												}
														}
											}
									}
						}
								}
					}
}
}
}
)