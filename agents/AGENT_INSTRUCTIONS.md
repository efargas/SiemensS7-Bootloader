# AI Coding Agent Instructions (Repository: SiemensS7-Bootloader)

## 🎯 **CURRENT PROJECT STATUS** (Updated: 2025-01-24)

### ✅ **COMPLETED PHASES**
- **Phase 1**: Project Foundation ✅ COMPLETE (100%)
- **Phase 2 - Task 2.1**: Repository Pattern Implementation ✅ COMPLETE (100%)
- **Phase 2 - Task 2.2**: Factory Pattern Enhancement ✅ COMPLETE (100%)
- **Phase 2 - Task 2.3**: Provider Pattern Core Implementation ✅ 80% COMPLETE

### 🔄 **NEXT PRIORITY TASK**
**Task 2.3**: Provider Pattern Completion (Final Phase)
- **Status**: Core implementation complete, DI extensions needed
- **Priority**: HIGH
- **Estimated Remaining Time**: 2-3 hours
- **Tracking**: `.copilot-tracking/changes/20250124-phase2-task3-provider-pattern.md`

### 📊 **BUILD STATUS**
- **Current**: ✅ SUCCESS (0 errors, 35 acceptable warnings)
- **Quality**: 🟢 EXCELLENT
- **Architecture**: Modern DI-based patterns with Provider Pattern 80% implemented

---

## 📋 **PURPOSE & SCOPE**

This project implements a modern C# bootloader utility with clean architecture patterns. Agents assist by producing code, tests, docs, and change-tracking artifacts following established conventions.

**Key Technologies**: .NET 8, Avalonia UI, Microsoft.Extensions.DependencyInjection, Repository Pattern, Factory Pattern, Provider Pattern

---

## 🛠️ **GENERAL RULES**

### **Code Quality Standards**
- Follow SOLID principles and established patterns (Repository, Factory, Provider)
- Use dependency injection throughout (`Microsoft.Extensions.DependencyInjection`)
- Implement proper async/await patterns with `ConfigureAwait(false)`
- Provide 100% XML documentation for public APIs
- Maintain backward compatibility with legacy components

### **File Modification Rules**
- Only modify files under `src/`, `tests/`, `docs/`, `.copilot-tracking/`, `agents/workspace/`
- Never delete existing tests or change production code behavior without adding tests
- Every code change must include at least one unit test or updated integration test
- When moving files, create adapters in old location with `[Obsolete]` for one release

---

## 🌿 **BRANCHING AND COMMITS**

### **Branch Naming**
- Feature branches: `feature/<short>-<desc>` (e.g., `feature/provider-pattern`)
- Chore branches: `chore/<desc>` (e.g., `chore/update-docs`)

### **Commit Standards**
- Write small commits (<200 LOC) with meaningful messages
- Use scope prefixes: `core:`, `ui:`, `services:`, `infrastructure:`, `tests:`
- Add plan reference: `"core: add IProviderFactory (plan: .copilot-tracking/changes/20250124-phase2-task3-provider-pattern.md)"`

---

## 📊 **PROGRESS TRACKING**

### **Implementation Tracking**
- Progress tracked in `.copilot-tracking/changes/YYYYMMDD-*.md` files
- For each completed task: Update plan file, append entry with Added/Modified/Removed files

### **Current Tracking Files**
- **Active**: `.copilot-tracking/changes/20250124-phase2-task3-provider-pattern.md`
- **Completed**: Repository and Factory pattern tracking files

---

## 🚀 **NEXT STEPS FOR AGENTS**

### **Immediate Priority: Provider Pattern Completion**
1. **Review Current Work**: Study completed provider interfaces and implementations
2. **Create DI Extensions**: Implement `ProviderServiceExtensions.cs` following established patterns
3. **Implement Specialized Providers**: Create FileSystem, Memory, and Caching providers
4. **Add Comprehensive Testing**: Unit tests for all provider components (>80% coverage)
5. **Validate Integration**: Ensure seamless integration with existing patterns

### **Success Criteria**
- ✅ Build passes: `dotnet build src/SiemensS7-Bootloader.sln` (0 errors)
- ✅ Tests pass: `dotnet test` (all existing + new tests)
- ✅ No breaking changes to existing APIs
- ✅ 100% XML documentation for new public APIs
- ✅ >80% test coverage for new provider code

---

## 🏗️ **ARCHITECTURE OVERVIEW**

### **Current Implementation Status**
```
✅ S7.Core.Abstractions/     # Interfaces and contracts
   ├── Repositories/         # Repository interfaces (Complete)
   ├── Factories/           # Factory interfaces (Complete)
   ├── Providers/           # Provider interfaces (Complete)
   └── Configuration/       # Configuration models (Complete)

✅ S7.Infrastructure/        # Implementation layer
   ├── Repositories/        # Repository implementations (Complete)
   ├── Factories/          # Factory implementations (Complete)
   └── Providers/          # Provider implementations (80% Complete)

✅ S7.Services/             # Service layer (Complete)
✅ S7.Core.Commands/        # Command layer with DI extensions
   ├── Extensions/         # DI registration extensions
   └── [NEXT] ProviderServiceExtensions.cs
```

### **Established Patterns**
- **Repository Pattern**: Generic CRUD with Unit of Work, specialized repositories
- **Factory Pattern**: DI-based creation, configuration-driven selection, abstract factories
- **Provider Pattern**: Service provider integration, discovery, configuration-based selection

---

## 📚 **REFERENCE MATERIALS**

### **For Next Agent**
1. **Detailed Briefing**: `agents/workspace/NEXT_AGENT_BRIEFING.md`
2. **Completion Instructions**: `agents/workspace/PROVIDER_PATTERN_COMPLETION_INSTRUCTIONS.md`
3. **Current Progress**: `.copilot-tracking/changes/20250124-phase2-task3-provider-pattern.md`
4. **Project Status**: `.copilot-tracking/plans/project-status-current.md`

### **Code Reference**
- **Provider Interfaces**: `src/S7_Csharp_Core/S7.Core.Abstractions/Providers/`
- **Provider Implementations**: `src/S7_Csharp_Core/S7.Infrastructure/Providers/`
- **DI Extensions Pattern**: `src/S7_Csharp_Core/S7.Core.Commands/Extensions/FactoryServiceExtensions.cs`
- **Testing Patterns**: `tests/S7.Core.Tests/`

---

## 🔒 **SECURITY AND SAFETY**

### **Restricted Areas**
- **DO NOT** modify files under `tools/`, `firmware/`, or payload locations
- **DO NOT** modify completed provider core implementations
- **DO NOT** change hardware integration code without explicit approval

### **Safe Development**
- All hardware interactions abstracted behind interfaces
- Use dependency injection for testability
- Implement comprehensive error handling and validation
- Follow principle of least privilege

---

## 🧪 **TESTING STRATEGY**

### **Test Coverage Requirements**
- Unit tests for all new public APIs (>80% coverage)
- Integration tests for DI container registration
- Mock-based testing for external dependencies
- Thread safety validation for concurrent operations

### **Test Organization**
```
tests/
├── S7.Core.Tests/           # Core logic tests
│   └── Providers/          # Provider-specific tests (TO CREATE)
├── S7_Csharp_Utility.Tests/ # UI tests
└── Integration tests        # Cross-component tests
```

---

## 📖 **DOCUMENTATION STANDARDS**

### **XML Documentation Requirements**
- 100% coverage for all new public APIs
- Include `<summary>`, `<param>`, `<returns>`, `<exception>`
- Provide usage examples for complex APIs
- Document thread safety and async behavior

---

## 🎯 **QUALITY STANDARDS**

### **Maintain 100% Success Rate**
- **Build Success**: All projects must compile without errors
- **Test Success**: All existing tests must continue to pass
- **Quality**: SOLID principles, comprehensive error handling
- **Performance**: No regression in existing operations
- **Compatibility**: No breaking changes to existing APIs

---

**Last Updated**: 2025-01-24  
**Project Health**: 🟢 EXCELLENT  
**Ready for**: Provider Pattern Completion (Final Phase)  
**Success Rate**: 100% (maintained across all completed phases)

**The project has a solid foundation with Repository, Factory, and Provider Pattern core implementations complete. Focus on completing DI extensions, specialized providers, and comprehensive testing to deliver a production-ready solution.**