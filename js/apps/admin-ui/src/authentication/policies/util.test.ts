import type { ConfigPropertyRepresentation } from "@keycloak/keycloak-admin-client/lib/defs/configPropertyRepresentation";
import type PasswordPolicyTypeRepresentation from "@keycloak/keycloak-admin-client/lib/defs/passwordPolicyTypeRepresentation";
import { describe, expect, it } from "vitest";
import {
  packPolicyValue,
  parsePolicy,
  serializePolicy,
  SubmittedValues,
  unpackPolicyValue,
} from "./util";

describe("serializePolicy", () => {
  it("returns an empty string if there are no policies", () => {
    expect(serializePolicy([], {})).toEqual("");
  });

  it("encodes the policies", () => {
    const policies: PasswordPolicyTypeRepresentation[] = [
      { id: "one" },
      { id: "two" },
    ];

    const submittedValues: SubmittedValues = {
      one: "value1",
      two: "value2",
    };

    expect(serializePolicy(policies, submittedValues)).toEqual(
      "one(value1) and two(value2)",
    );
  });
});

describe("parsePolicy", () => {
  it("returns an empty array if an empty value is passed", () => {
    expect(parsePolicy("", [])).toEqual([]);
  });

  it("parses the policy", () => {
    const policies: PasswordPolicyTypeRepresentation[] = [
      { id: "one" },
      { id: "two" },
    ];

    expect(parsePolicy("one(value1) and two", policies)).toEqual([
      { id: "one", value: "value1" },
      { id: "two" },
    ]);
  });

  it("parses the policy and trims excessive whitespace", () => {
    const policies: PasswordPolicyTypeRepresentation[] = [
      { id: "one" },
      { id: "two" },
    ];

    expect(parsePolicy("one( value1 ) and  two ", policies)).toEqual([
      { id: "one", value: "value1" },
      { id: "two" },
    ]);
  });

  it("parses the policy and it handles unescaped values", () => {
    const policies: PasswordPolicyTypeRepresentation[] = [{ id: "one" }];

    expect(parsePolicy("one(value1", policies)).toEqual([{ id: "one" }]);
  });

  it("parses the policy and preserves nested parentheses", () => {
    const policies: PasswordPolicyTypeRepresentation[] = [{ id: "one" }];

    expect(parsePolicy("one(value1))", policies)).toEqual([
      { id: "one", value: "value1)" },
    ]);
  });

  it("parses the policy and preserves only existing entries", () => {
    const policies: PasswordPolicyTypeRepresentation[] = [{ id: "two" }];

    expect(parsePolicy("one(value1) and two", policies)).toEqual([
      { id: "two" },
    ]);
  });
});

const properties: ConfigPropertyRepresentation[] = [
  { name: "length", type: "Integer", defaultValue: "3" as unknown as object },
  {
    name: "caseInsensitive",
    type: "boolean",
    defaultValue: "true" as unknown as object,
  },
  { name: "prefix", type: "String" },
];

describe("unpackPolicyValue", () => {
  it("maps segments to properties by position", () => {
    expect(unpackPolicyValue("5,false,abc", properties)).toEqual({
      length: "5",
      caseInsensitive: "false",
      prefix: "abc",
    });
  });

  it("fills missing trailing segments with property defaults", () => {
    expect(unpackPolicyValue("5", properties)).toEqual({
      length: "5",
      caseInsensitive: "true",
      prefix: "",
    });
  });

  it("uses defaults for an undefined value", () => {
    expect(unpackPolicyValue(undefined, properties)).toEqual({
      length: "3",
      caseInsensitive: "true",
      prefix: "",
    });
  });

  it("trims whitespace around segments", () => {
    expect(unpackPolicyValue(" 5 , false ,abc", properties)).toEqual({
      length: "5",
      caseInsensitive: "false",
      prefix: "abc",
    });
  });
});

describe("packPolicyValue", () => {
  it("joins values in property order", () => {
    expect(
      packPolicyValue(
        { prefix: "abc", length: "5", caseInsensitive: "false" },
        properties,
      ),
    ).toEqual("5,false,abc");
  });

  it("falls back to property defaults for missing values", () => {
    expect(packPolicyValue({ length: "5" }, properties)).toEqual("5,true,");
  });

  it("round-trips with unpackPolicyValue", () => {
    const values = unpackPolicyValue("7,false,xyz", properties);
    expect(packPolicyValue(values, properties)).toEqual("7,false,xyz");
  });
});
