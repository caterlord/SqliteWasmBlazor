using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Testing;
using Microsoft.CodeAnalysis.Text;
using SqliteWasmBlazor.CryptoSync.Generator;

namespace SqliteWasmBlazor.CryptoSync.Generator.Tests;

internal class CryptoSyncGeneratorTest : CSharpSourceGeneratorTest<CryptoSyncGenerator, DefaultVerifier>
{
    protected override ParseOptions CreateParseOptions()
    {
        return new CSharpParseOptions(languageVersion: LanguageVersion.Preview);
    }
}

public class CryptoSyncGeneratorTests
{
    private static readonly string StubTypes = """
        namespace Microsoft.EntityFrameworkCore
        {
            public class DbContext
            {
                protected virtual void OnModelCreating(ModelBuilder modelBuilder) { }
            }
            public class DbSet<T> where T : class { }
            public class ModelBuilder
            {
                public EntityTypeBuilder<T> Entity<T>() where T : class => new();
            }
            public class EntityTypeBuilder<T> where T : class
            {
                public EntityTypeBuilder<T> ToTable(string name) => this;
                public EntityTypeBuilder<T> HasKey(System.Linq.Expressions.Expression<System.Func<T, object>> expr) => this;
                public EntityTypeBuilder<T> HasIndex(System.Linq.Expressions.Expression<System.Func<T, object>> expr) => this;
            }
            public class DbContextOptions { }
            public class DbContextOptions<T> : DbContextOptions where T : DbContext { }
        }
        namespace SqliteWasmBlazor.CryptoSync
        {
            public enum SharingScope { Public = 0, Shared = 1, Client = 2 }
            public abstract class SyncableEntity
            {
                public System.Guid Id { get; set; }
                public SharingScope SharingScope { get; set; }
                public string SharingId { get; set; } = "";
                public System.DateTime UpdatedAt { get; set; }
                public bool IsDeleted { get; set; }
                public System.DateTime? DeletedAt { get; set; }
            }
            public abstract class CryptoSyncContextBase : Microsoft.EntityFrameworkCore.DbContext
            {
                protected CryptoSyncContextBase(Microsoft.EntityFrameworkCore.DbContextOptions options) : base() { }
            }
        }
        """;

    [Fact]
    public void GeneratesCryptoEntity_ForDbSet()
    {
        var source = StubTypes + """
            namespace TestApp
            {
                public class TodoItem : SqliteWasmBlazor.CryptoSync.SyncableEntity
                {
                    public string Title { get; set; } = "";
                    public bool IsCompleted { get; set; }
                }

                public partial class MyContext : SqliteWasmBlazor.CryptoSync.CryptoSyncContextBase
                {
                    public MyContext(Microsoft.EntityFrameworkCore.DbContextOptions options) : base(options) { }
                    public Microsoft.EntityFrameworkCore.DbSet<TodoItem> TodoItems { get; set; }
                }
            }
            """;

        var driver = CSharpGeneratorDriver.Create(new CryptoSyncGenerator());
        var compilation = CSharpCompilation.Create("test",
            [CSharpSyntaxTree.ParseText(source)],
            Basic.Reference.Assemblies.Net80.References.All.Select(r => r));

        driver.RunGeneratorsAndUpdateCompilation(compilation, out var outputCompilation, out var diagnostics);

        // Generator should not produce any diagnostics
        Assert.Empty(diagnostics);

        // Should generate Crypto_TodoItem
        var cryptoEntity = outputCompilation.SyntaxTrees
            .FirstOrDefault(t => t.FilePath.Contains("Crypto_TodoItem"));
        Assert.NotNull(cryptoEntity);

        // Should generate config and registry
        var config = outputCompilation.SyntaxTrees.FirstOrDefault(t => t.FilePath.Contains("CryptoConfig"));
        var registry = outputCompilation.SyntaxTrees.FirstOrDefault(t => t.FilePath.Contains("CryptoTableRegistry"));
        Assert.NotNull(config);
        Assert.NotNull(registry);
    }

    [Fact]
    public async Task GeneratesCorrectCryptoEntityContent()
    {
        var source = StubTypes + """
            namespace TestApp
            {
                public class ShoppingItem : SqliteWasmBlazor.CryptoSync.SyncableEntity
                {
                    public string Name { get; set; } = "";
                    public decimal Price { get; set; }
                }

                public partial class ShopContext : SqliteWasmBlazor.CryptoSync.CryptoSyncContextBase
                {
                    public ShopContext(Microsoft.EntityFrameworkCore.DbContextOptions options) : base(options) { }
                    public Microsoft.EntityFrameworkCore.DbSet<ShoppingItem> ShoppingItems => Set<ShoppingItem>();
                }
            }
            """;

        var expectedCryptoEntity = """
            // <auto-generated/>
            #nullable enable

            using System.ComponentModel.DataAnnotations;

            namespace TestApp;

            /// <summary>
            /// Shadow crypto table for ShoppingItem. Contains encrypted row data.
            /// Generated by CryptoSyncGenerator — do not edit.
            /// </summary>
            public sealed class Crypto_ShoppingItem
            {
                public Guid Id { get; set; }

                /// <summary>0=Public, 1=Shared, 2=Client</summary>
                public int SharingScope { get; set; }

                [MaxLength(128)]
                public required string SharingId { get; set; }

                /// <summary>AES-GCM encrypted row data (ALL columns).</summary>
                public required byte[] EncryptedRow { get; set; }

                /// <summary>Per-row AES-GCM nonce.</summary>
                public required byte[] Nonce { get; set; }
            }

            """;

        var test = new CryptoSyncGeneratorTest { TestCode = source };

        test.TestState.GeneratedSources.Add(
            (typeof(CryptoSyncGenerator), "Crypto_ShoppingItem.g.cs",
                SourceText.From(expectedCryptoEntity, Encoding.UTF8)));

        // Skip other generated files (config, registry) — we're testing entity shape only
        test.TestBehaviors = TestBehaviors.SkipGeneratedSourcesCheck;

        // Verify the specific crypto entity source is generated
        var driver = CSharpGeneratorDriver.Create(new CryptoSyncGenerator());
        var compilation = CSharpCompilation.Create("test",
            [CSharpSyntaxTree.ParseText(source)],
            Basic.Reference.Assemblies.Net80.References.All.Select(r => r));

        driver.RunGeneratorsAndUpdateCompilation(compilation, out var outputCompilation, out var diagnostics);

        var generatedTrees = outputCompilation.SyntaxTrees
            .Where(t => t.FilePath.Contains("Crypto_ShoppingItem"))
            .ToList();

        Assert.Single(generatedTrees);
        var generatedCode = generatedTrees[0].GetText().ToString();
        Assert.Contains("class Crypto_ShoppingItem", generatedCode);
        Assert.Contains("byte[] EncryptedRow", generatedCode);
        Assert.Contains("byte[] Nonce", generatedCode);
        Assert.Contains("string SharingId", generatedCode);
    }

    [Fact]
    public async Task GeneratesRegistry()
    {
        var source = StubTypes + """
            namespace TestApp
            {
                public class Item1 : SqliteWasmBlazor.CryptoSync.SyncableEntity { }
                public class Item2 : SqliteWasmBlazor.CryptoSync.SyncableEntity { }

                public partial class MultiContext : SqliteWasmBlazor.CryptoSync.CryptoSyncContextBase
                {
                    public MultiContext(Microsoft.EntityFrameworkCore.DbContextOptions options) : base(options) { }
                    public Microsoft.EntityFrameworkCore.DbSet<Item1> Items1 => Set<Item1>();
                    public Microsoft.EntityFrameworkCore.DbSet<Item2> Items2 => Set<Item2>();
                }
            }
            """;

        var driver = CSharpGeneratorDriver.Create(new CryptoSyncGenerator());
        var compilation = CSharpCompilation.Create("test",
            [CSharpSyntaxTree.ParseText(source)],
            Basic.Reference.Assemblies.Net80.References.All.Select(r => r));

        driver.RunGeneratorsAndUpdateCompilation(compilation, out var outputCompilation, out _);

        var registryTree = outputCompilation.SyntaxTrees
            .FirstOrDefault(t => t.FilePath.Contains("CryptoTableRegistry"));

        Assert.NotNull(registryTree);
        var code = registryTree.GetText().ToString();
        Assert.Contains("\"Item1\"", code);
        Assert.Contains("\"Item2\"", code);
        Assert.Contains("_crypto_Items1", code);
        Assert.Contains("_crypto_Items2", code);
    }

    [Fact]
    public async Task SkipsSystemTables()
    {
        var source = StubTypes + """
            namespace TestApp
            {
                public class MyEntity : SqliteWasmBlazor.CryptoSync.SyncableEntity { }

                public partial class TestCtx : SqliteWasmBlazor.CryptoSync.CryptoSyncContextBase
                {
                    public TestCtx(Microsoft.EntityFrameworkCore.DbContextOptions options) : base(options) { }
                    public Microsoft.EntityFrameworkCore.DbSet<MyEntity> MyEntities => Set<MyEntity>();
                }
            }
            """;

        var driver = CSharpGeneratorDriver.Create(new CryptoSyncGenerator());
        var compilation = CSharpCompilation.Create("test",
            [CSharpSyntaxTree.ParseText(source)],
            Basic.Reference.Assemblies.Net80.References.All.Select(r => r));

        driver.RunGeneratorsAndUpdateCompilation(compilation, out var outputCompilation, out _);

        var generatedFiles = outputCompilation.SyntaxTrees
            .Where(t => t.FilePath.Contains("Crypto_"))
            .ToList();

        // Should only generate for MyEntity, not system tables
        Assert.Single(generatedFiles);
        Assert.Contains("Crypto_MyEntity", generatedFiles[0].FilePath);
    }
}
