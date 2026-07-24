import type { ConfigPropertyRepresentation } from "@keycloak/keycloak-admin-client/lib/defs/configPropertyRepresentation";
import type PasswordPolicyTypeRepresentation from "@keycloak/keycloak-admin-client/lib/defs/passwordPolicyTypeRepresentation";
import {
  Button,
  FormGroup,
  NumberInput,
  Split,
  SplitItem,
  Stack,
  StackItem,
  Switch,
  TextInput,
  ValidatedOptions,
} from "@patternfly/react-core";
import { MinusCircleIcon } from "@patternfly/react-icons";
import { useMemo } from "react";
import { Controller, useFormContext } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { FormErrorText, HelpItem } from "@keycloak/keycloak-ui-shared";

import { useServerInfo } from "../../context/server-info/ServerInfoProvider";
import { packPolicyValue, unpackPolicyValue } from "./util";

import "./policy-row.css";

const PASSWORD_POLICY_PROVIDER_CLASS =
  "org.keycloak.policy.PasswordPolicyProvider";

type PolicyRowProps = {
  policy: PasswordPolicyTypeRepresentation;
  onRemove: (id?: string) => void;
};

type PolicyMultiFieldProps = {
  policyId: string;
  properties: ConfigPropertyRepresentation[];
};

const PolicyMultiField = ({ policyId, properties }: PolicyMultiFieldProps) => {
  const { t } = useTranslation();
  const { setValue, watch } = useFormContext();

  const packed = watch(policyId) as string | undefined;
  const values = unpackPolicyValue(packed, properties);

  const onFieldChange = (name: string, fieldValue: string) =>
    setValue(
      policyId,
      packPolicyValue({ ...values, [name]: fieldValue }, properties),
      { shouldDirty: true },
    );

  return (
    <Stack hasGutter>
      {properties.map((property) => {
        const name = property.name!;
        const value = values[name];
        const fieldId = `${policyId}-${name}`;
        const label = t(property.label ?? name);

        return (
          <StackItem key={name}>
            <FormGroup
              label={label}
              fieldId={fieldId}
              labelIcon={
                property.helpText ? (
                  <HelpItem
                    helpText={t(property.helpText)}
                    fieldLabelId={fieldId}
                  />
                ) : undefined
              }
            >
              {property.type === "boolean" ? (
                <Switch
                  id={fieldId}
                  data-testid={fieldId}
                  label={t("on")}
                  labelOff={t("off")}
                  isChecked={value === "true"}
                  onChange={(_event, checked) =>
                    onFieldChange(name, checked.toString())
                  }
                  aria-label={label}
                />
              ) : property.type === "Integer" ? (
                <NumberInput
                  id={fieldId}
                  data-testid={fieldId}
                  value={Number(value) || 0}
                  min={0}
                  onPlus={() =>
                    onFieldChange(name, String((Number(value) || 0) + 1))
                  }
                  onMinus={() =>
                    onFieldChange(
                      name,
                      String(Math.max((Number(value) || 0) - 1, 0)),
                    )
                  }
                  onChange={(event) => {
                    const newValue = Number(event.currentTarget.value);
                    onFieldChange(
                      name,
                      String(isNaN(newValue) ? 0 : Math.max(newValue, 0)),
                    );
                  }}
                  className="keycloak__policies_authentication__number-field"
                />
              ) : (
                <TextInput
                  id={fieldId}
                  data-testid={fieldId}
                  value={value}
                  onChange={(_event, newValue) => onFieldChange(name, newValue)}
                />
              )}
            </FormGroup>
          </StackItem>
        );
      })}
    </Stack>
  );
};

export const PolicyRow = ({
  policy: { id, configType, defaultValue, displayName },
  onRemove,
}: PolicyRowProps) => {
  const { t } = useTranslation();
  const {
    control,
    register,
    formState: { errors },
  } = useFormContext();
  const { componentTypes } = useServerInfo();

  const properties = useMemo(
    () =>
      componentTypes?.[PASSWORD_POLICY_PROVIDER_CLASS]?.find(
        (componentType) => componentType.id === id,
      )?.properties,
    [componentTypes, id],
  );

  // Policies that declare more than one configuration property through
  // ConfiguredProvider get one typed input per property; the fields write
  // through to the single packed policy value, so the stored format and the
  // save flow stay unchanged.
  const multiField =
    properties !== undefined && properties.length > 1 && !!configType;

  const error = errors[id!];

  return (
    <FormGroup
      label={displayName}
      fieldId={id!}
      isRequired
      labelIcon={
        <HelpItem
          helpText={t(`passwordPoliciesHelp.${id}`)}
          fieldLabelId={id!}
        />
      }
    >
      <Split>
        <SplitItem isFilled>
          {multiField && (
            <PolicyMultiField policyId={id!} properties={properties} />
          )}
          {!multiField && configType && configType !== "int" && (
            <TextInput
              id={id}
              data-testid={id}
              {...register(id!, { required: true })}
              defaultValue={defaultValue}
              validated={
                error ? ValidatedOptions.error : ValidatedOptions.default
              }
            />
          )}
          {!multiField && configType === "int" && (
            <Controller
              name={id!}
              defaultValue={Number.parseInt(defaultValue || "0")}
              control={control}
              render={({ field }) => {
                const MIN_VALUE = 0;
                const setValue = (newValue: number) =>
                  field.onChange(Math.max(newValue, MIN_VALUE));
                const value = Number(field.value);

                return (
                  <NumberInput
                    id={id}
                    value={value}
                    min={MIN_VALUE}
                    onPlus={() => setValue(value + 1)}
                    onMinus={() => setValue(value - 1)}
                    onChange={(event) => {
                      const newValue = Number(event.currentTarget.value);
                      setValue(!isNaN(newValue) ? newValue : 0);
                    }}
                    className="keycloak__policies_authentication__number-field"
                  />
                );
              }}
            />
          )}
          {!multiField && !configType && (
            <Switch
              id={id!}
              label={t("on")}
              labelOff={t("off")}
              isChecked
              isDisabled
              aria-label={displayName}
            />
          )}
        </SplitItem>
        <SplitItem>
          <Button
            data-testid={`remove-${id}`}
            variant="link"
            className="keycloak__policies_authentication__minus-icon"
            onClick={() => onRemove(id)}
            aria-label={t("remove")}
          >
            <MinusCircleIcon />
          </Button>
        </SplitItem>
      </Split>
      {error && <FormErrorText message={t("required")} />}
    </FormGroup>
  );
};
