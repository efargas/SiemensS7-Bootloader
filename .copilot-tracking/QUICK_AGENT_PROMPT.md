# Quick Agent Prompt - MainWindowViewModel Refactoring

## Your Mission
You are implementing the MainWindowViewModel refactoring plan to eliminate SRP violations by extracting feature ViewModels. Transform a "God Class" with 14 dependencies into a clean orchestrator.

## MANDATORY: Read These Files First
1. `.copilot-tracking/plans/20250126-mainwindowviewmodel-refactoring-plan.md` - Complete plan with 35 tasks
2. `.copilot-tracking/details/20250126-mainwindowviewmodel-refactoring-details.md` - Implementation details for each task
3. `.copilot-tracking/changes/20250126-mainwindowviewmodel-refactoring-changes.md` - Current progress tracking
4. `src/S7_Csharp_Utility/ViewModels/MainWindowViewModel.cs` - The target file to refactor

## Implementation Process
1. **Find Next Task**: Look for next unchecked `[ ]` task in plan file
2. **Read Details**: Read that task's section in details file completely
3. **Implement**: Create working code following existing project patterns
4. **Update Plan**: Mark task complete `[x]` in plan file
5. **Update Changes**: Add entry to changes file with file paths and description

## Required After Each Task
**Update changes file** by appending to appropriate section:
```markdown
### Added
- src/path/to/NewFile.cs - Brief description of implementation

### Modified  
- src/path/to/ExistingFile.cs - Brief description of changes
```

**Create handoff summary**:
```markdown
## Task [X.Y] Complete
**Completed**: [Task description]
**Files Changed**: [List]
**Next Task**: [X.Y+1] - [Description]
**Status**: Ready/Blocked/Needs attention
```

## Code Standards
- Use primary constructors, async/await with ConfigureAwait(false)
- Follow existing ViewModelBase patterns
- Include XML documentation
- Use AsyncRelayCommand pattern
- Proper error handling with structured logging

## Success Target
- Reduce MainWindowViewModel from 14 to ≤8 dependencies
- Extract 4 feature ViewModels + 2 state services
- Preserve all existing functionality
- Maintain project's architectural excellence

**Start by reading the plan file to understand the complete scope, then identify the first unchecked task to implement.**