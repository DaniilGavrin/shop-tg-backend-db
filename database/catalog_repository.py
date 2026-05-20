from database.db import db

class CatalogRepository:

    async def get_catalog(self):
        query = """
            SELECT id, name, base_price_rub, slug, category, preview_image
            FROM products
        """

        rows = await db.fetch(query)

        return [dict(row) for row in rows]

    async def get_catalog_item(self, item_id: int):
        query = """
        SELECT *
        FROM products
        WHERE id = $1
        """

        row = await db.fetchrow(query, item_id)

        return dict(row) if row else None


catalog_repo = CatalogRepository()