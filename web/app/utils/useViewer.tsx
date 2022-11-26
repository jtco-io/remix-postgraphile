import React, { ReactNode } from "react";
import { ViewerQuery, useViewerQuery } from "./useViewerQuery.generated";
export type Viewer = ViewerQuery["viewer"];

const ViewerContext = React.createContext<{
  viewer: Viewer;
  loading: boolean;
}>({
  viewer: undefined,
  loading: false,
});

export const ViewerContextContainer = (props: { children: ReactNode }) => {
  const { data, loading } = useViewerQuery();
  return (
    <ViewerContext.Provider value={{ viewer: data?.viewer, loading }}>
      {props.children}
    </ViewerContext.Provider>
  );
};

const useViewer = () => React.useContext(ViewerContext);

export default useViewer;
