using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SqliteWasmBlazor.Models;

public class NoteDbContextFactory : IDesignTimeDbContextFactory<NoteDbContext>
{
    public NoteDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<NoteDbContext>();
        optionsBuilder.UseSqlite("Data Source=:memory:");
        return new NoteDbContext(optionsBuilder.Options);
    }
}
