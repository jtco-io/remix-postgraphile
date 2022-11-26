import React from "react";

export interface FormProps
  extends Pick<
    React.DetailedHTMLProps<
      React.FormHTMLAttributes<HTMLFormElement>,
      HTMLFormElement
    >,
    "children"
  > {
  id?: string;
  onSubmit: () => unknown | Promise<unknown>;
  className?: string;
}

export default function Form(props: FormProps): JSX.Element {
  const onSubmit = React.useCallback(
    async (e: React.ChangeEvent<HTMLFormElement>) => {
      e.preventDefault();
      await props.onSubmit();
    },
    [props]
  );
  let classname = "flex-col w-full";
  if (props.className) {
    classname = `${classname} ${props.className}`;
  }

  return (
    <form id={props.id} onSubmit={onSubmit} className={classname}>
      {props.children}
    </form>
  );
}
