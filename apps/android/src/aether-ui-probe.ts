import { oneOf, IP_FAMILIES, type IpFamily } from "../../../packages/ui/src/enums";
export const probe: IpFamily | null = oneOf(window.document.title, IP_FAMILIES, "v4");
