import React from "react";

type InputProps = React.DetailedHTMLProps<
  React.InputHTMLAttributes<HTMLInputElement>,
  HTMLInputElement
>;

type RequiredInputProps = Required<
  Pick<InputProps, "name" | "placeholder" | "value" | "onChange">
>;

type OptionalInputProps = Pick<
  InputProps,
  "autoComplete" | "required" | "maxLength" | "pattern" | "title"
>;

export type TextFieldProps = RequiredInputProps &
  OptionalInputProps & {
    type?: "email" | "password" | "url";
  };

export default function TextField(props: TextFieldProps): JSX.Element {
  return <input {...props} />;
}
