/** Shown by result views when no analysis is loaded yet. */
export function NoAnalysis({ message }: { message?: string }) {
  return (
    <div className="view">
      <div className="note">
        <p className="note-title">No analysis loaded</p>
        <p>{message ?? 'Upload a capture or open a record from the history to see its results here.'}</p>
      </div>
    </div>
  )
}
